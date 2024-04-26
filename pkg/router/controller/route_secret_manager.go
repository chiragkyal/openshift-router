package controller

import (
	"context"
	"fmt"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/authorization/authorizationutil"
	"github.com/openshift/library-go/pkg/route/secretmanager"
	"github.com/openshift/router/pkg/router"
	authorizationv1 "k8s.io/api/authorization/v1"
	kapi "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authentication/user"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

const (
	// routerServiceAccount is used to validate RBAC permissions for externalCertificate
	routerServiceAccount = "system:serviceaccount:openshift-ingress:router"
)

// RouteSecretManager implements the router.Plugin interface to register
// or unregister route with secretManger if externalCertificate is used.
// It also reads the referenced secret to update in-memory tls.Certificate and tls.Key
type RouteSecretManager struct {
	// plugin is the next plugin in the chain.
	plugin router.Plugin
	// recorder is an interface for indicating route status.
	recorder RouteStatusRecorder

	secretManager secretmanager.SecretManager
	secretsGetter corev1client.SecretsGetter
	sarClient     authorizationclient.SubjectAccessReviewInterface
}

// NewRouteSecretManager creates a plugin wrapper that ....
func NewRouteSecretManager(plugin router.Plugin, recorder RouteStatusRecorder, secretManager secretmanager.SecretManager, secretsGetter corev1client.SecretsGetter, sarClient authorizationclient.SubjectAccessReviewInterface) *RouteSecretManager {
	return &RouteSecretManager{
		plugin:        plugin,
		recorder:      recorder,
		secretManager: secretManager,
		secretsGetter: secretsGetter,
		sarClient:     sarClient,
	}
}

func (p *RouteSecretManager) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	return p.plugin.HandleNode(eventType, node)
}

func (p *RouteSecretManager) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	return p.plugin.HandleEndpoints(eventType, endpoints)
}

func (p *RouteSecretManager) HandleNamespaces(namespaces sets.String) error {
	return p.plugin.HandleNamespaces(namespaces)
}

func (p *RouteSecretManager) Commit() error {
	return p.plugin.Commit()
}

func (p *RouteSecretManager) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	klog.Info("Executing RouteSecretManager plugin...")

	switch eventType {
	case watch.Added:
		// create new watch
		if err := p.validateAndRegister(route); err != nil {
			return err
		}

	case watch.Modified:
		// remove old watch
		if p.secretManager.IsRouteRegistered(route.Namespace, route.Name) {
			if err := p.secretManager.UnregisterRoute(route.Namespace, route.Name); err != nil {
				klog.Error("failed to unregister route", err)
				return err
			}
		}
		// create new watch
		if err := p.validateAndRegister(route); err != nil {
			return err
		}

	case watch.Deleted:
		// remove old watch
		if p.secretManager.IsRouteRegistered(route.Namespace, route.Name) {
			if err := p.secretManager.UnregisterRoute(route.Namespace, route.Name); err != nil {
				klog.Error("failed to unregister route", err)
				return err
			}
		}
	default:
		return fmt.Errorf("invalid eventType %v", eventType)
	}

	// call next plugin
	return p.plugin.HandleRoute(eventType, route)
}

func (p *RouteSecretManager) validateAndRegister(route *routev1.Route) error {

	if err := validate(route, p.sarClient, p.secretsGetter).ToAggregate(); err != nil {
		klog.Error(err, "skipping route due to invalid externalCertificate configuration", " route ", route.Name)
		p.recorder.RecordRouteRejection(route, "ExternalCertificateValidationFailed", err.Error())
		p.plugin.HandleRoute(watch.Deleted, route)
		return fmt.Errorf("invalid route configuration for externalCertificate")
	}

	if hasExternalCertificate(route) {
		// register route with secretManager
		secreth := p.generateSecretHandler(route)
		if err := p.secretManager.RegisterRoute(context.TODO(), route.Namespace, route.Name, getReferencedSecret(route), secreth); err != nil {
			klog.Error("failed to register route", err)
			return err
		}
		// read referenced secret
		secret, err := p.secretManager.GetSecret(context.TODO(), route.Namespace, route.Name)
		if err != nil {
			klog.Error("failed to read referenced secret", err)
			return err
		}
		// update tls.Certificate and tls.Key
		// NOTE: this will be in-memory change and won't update actual route resource
		route.Spec.TLS.Certificate = string(secret.Data["tls.crt"])
		route.Spec.TLS.Key = string(secret.Data["tls.key"])
	}

	return nil
}

func (p *RouteSecretManager) generateSecretHandler(route *routev1.Route) cache.ResourceEventHandlerFuncs {
	// secret handler
	secreth := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret := obj.(*kapi.Secret)
			klog.Infof("secret %s added for %s/%s", secret.Name, route.Namespace, route.Name)
			// Do nothing for add event
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			secretOld := old.(*kapi.Secret)
			secretNew := new.(*kapi.Secret)
			klog.Infof("secret %s updated: old version %s, new version %s for %s/%s", secretNew.Name, secretOld.ResourceVersion, secretNew.ResourceVersion, route.Namespace, route.Name)

			// we need to re-validate
			if err := validate(route, p.sarClient, p.secretsGetter).ToAggregate(); err != nil {
				klog.Error(err, "skipping route due to invalid externalCertificate configuration", " route ", route.Name)
				p.recorder.RecordRouteRejection(route, "ExternalCertificateValidationFailed", err.Error())
				p.plugin.HandleRoute(watch.Deleted, route)
			}

			// read referenced secret (updated data)
			secret, err := p.secretManager.GetSecret(context.TODO(), route.Namespace, route.Name)
			if err != nil {
				klog.Error("failed to read referenced secret", err)
				p.recorder.RecordRouteRejection(route, "ExternalCertificateReadFailed", err.Error())
				p.plugin.HandleRoute(watch.Deleted, route)
			}

			// update tls.Certificate and tls.Key
			route.Spec.TLS.Certificate = string(secret.Data["tls.crt"])
			route.Spec.TLS.Key = string(secret.Data["tls.key"])

			// call the next plugin with watch.Modified
			p.plugin.HandleRoute(watch.Modified, route)
		},
		DeleteFunc: func(obj interface{}) {
			secret := obj.(*kapi.Secret)
			err := fmt.Errorf("secret %s deleted for %s/%s", secret.Name, route.Namespace, route.Name)
			klog.Error(err)
			p.recorder.RecordRouteRejection(route, "ExternalCertificateSecretDeleted", err.Error())
			p.plugin.HandleRoute(watch.Deleted, route)
		},
	}
	return secreth
}

func hasExternalCertificate(route *routev1.Route) bool {
	tls := route.Spec.TLS
	if tls != nil && tls.ExternalCertificate != nil && len(tls.ExternalCertificate.Name) > 0 {
		return true
	}
	return false
}

// must be called after hasExternalCertificate
func getReferencedSecret(route *routev1.Route) string {
	secretName := route.Spec.TLS.ExternalCertificate.Name
	klog.Info("Referenced secretName: ", secretName)
	return secretName
}

func validate(route *routev1.Route, sarc authorizationclient.SubjectAccessReviewInterface, secrets corev1client.SecretsGetter) field.ErrorList {
	result := field.ErrorList{}
	tls := route.Spec.TLS
	fldPath := field.NewPath("spec").Child("tls")

	// no tls config present, no need for validation
	if tls == nil {
		return nil
	}

	switch tls.Termination {
	case routev1.TLSTerminationReencrypt, routev1.TLSTerminationEdge:
		if tls.ExternalCertificate != nil {
			if len(tls.Certificate) > 0 && len(tls.ExternalCertificate.Name) > 0 {
				result = append(result, field.Invalid(fldPath.Child("externalCertificate"), tls.ExternalCertificate.Name, "cannot specify both tls.certificate and tls.externalCertificate"))
			} else if len(tls.ExternalCertificate.Name) > 0 {
				errs := validateTLSExternalCertificate(route, fldPath.Child("externalCertificate"), sarc, secrets)
				result = append(result, errs...)
			}
		}
	//passthrough term should not specify any cert
	case routev1.TLSTerminationPassthrough:
		if tls.ExternalCertificate != nil {
			if len(tls.ExternalCertificate.Name) > 0 {
				result = append(result, field.Invalid(fldPath.Child("externalCertificate"), tls.ExternalCertificate.Name, "passthrough termination does not support certificates"))
			}
		}
	default:
		validValues := []string{string(routev1.TLSTerminationEdge), string(routev1.TLSTerminationPassthrough), string(routev1.TLSTerminationReencrypt)}
		result = append(result, field.NotSupported(fldPath.Child("termination"), tls.Termination, validValues))
	}

	return result
}

// validateTLSExternalCertificate tests different pre-conditions required for
// using externalCertificate. Called by validateTLS.
func validateTLSExternalCertificate(route *routev1.Route, fldPath *field.Path, sarc authorizationclient.SubjectAccessReviewInterface, secretsGetter corev1client.SecretsGetter) field.ErrorList {
	tls := route.Spec.TLS

	errs := field.ErrorList{}
	// The router serviceaccount must have permission to get/list/watch the referenced secret.
	// The role and rolebinding to provide this access must be provided by the user.
	if err := authorizationutil.Authorize(sarc, &user.DefaultInfo{Name: routerServiceAccount},
		&authorizationv1.ResourceAttributes{
			Namespace: route.Namespace,
			Verb:      "get",
			Resource:  "secrets",
			Name:      tls.ExternalCertificate.Name,
		}); err != nil {
		errs = append(errs, field.Forbidden(fldPath, "router serviceaccount does not have permission to get this secret"))
	}

	if err := authorizationutil.Authorize(sarc, &user.DefaultInfo{Name: routerServiceAccount},
		&authorizationv1.ResourceAttributes{
			Namespace: route.Namespace,
			Verb:      "watch",
			Resource:  "secrets",
			Name:      tls.ExternalCertificate.Name,
		}); err != nil {
		errs = append(errs, field.Forbidden(fldPath, "router serviceaccount does not have permission to watch this secret"))
	}

	if err := authorizationutil.Authorize(sarc, &user.DefaultInfo{Name: routerServiceAccount},
		&authorizationv1.ResourceAttributes{
			Namespace: route.Namespace,
			Verb:      "list",
			Resource:  "secrets",
			Name:      tls.ExternalCertificate.Name,
		}); err != nil {
		errs = append(errs, field.Forbidden(fldPath, "router serviceaccount does not have permission to list this secret"))
	}

	// The secret should be in the same namespace as that of the route.
	secret, err := secretsGetter.Secrets(route.Namespace).Get(context.TODO(), tls.ExternalCertificate.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return append(errs, field.NotFound(fldPath, err))
		}
		return append(errs, field.InternalError(fldPath, err))
	}

	// The secret should be of type kubernetes.io/tls
	if secret.Type != kapi.SecretTypeTLS {
		errs = append(errs, field.Invalid(fldPath, tls.ExternalCertificate.Name, fmt.Sprintf("secret of type %q required", kapi.SecretTypeTLS)))
	}

	return errs
}
