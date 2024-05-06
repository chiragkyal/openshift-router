package controller

import (
	"context"
	"fmt"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/route/secretmanager"
	"github.com/openshift/router/pkg/router"
	"github.com/openshift/router/pkg/router/routeapihelpers"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/watch"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
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

// NewRouteSecretManager creates a new instance of RouteSecretManager.
// It wraps the provided plugin and adds secret management capabilities.
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

// HandleRoute manages the registration, unregistration, and validation of routes with external certificates.
// For Added events, it validates the route's external certificate configuration and registers it with the secret manager.
// For Modified events, it first unregisters the route if it's already registered and then revalidates and registers it again.
// For Deleted events, it unregisters the route if it's registered.
// Additionally, it delegates the handling of the event to the next plugin in the chain after performing the necessary actions.
func (p *RouteSecretManager) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	log.V(10).Info("HandleRoute: RouteSecretManager", "eventType", eventType)

	switch eventType {
	case watch.Added:
		// register with secret monitor
		if hasExternalCertificate(route) {
			if err := p.validateAndRegister(route); err != nil {
				return err
			}
		}

	case watch.Modified:
		// unregister associated secret monitor, if registered
		if p.secretManager.IsRouteRegistered(route.Namespace, route.Name) {
			if err := p.secretManager.UnregisterRoute(route.Namespace, route.Name); err != nil {
				log.Error(err, "failed to unregister route")
				return err
			}
		}
		// register with secret monitor
		if hasExternalCertificate(route) {
			if err := p.validateAndRegister(route); err != nil {
				return err
			}
		}

	case watch.Deleted:
		// unregister associated secret monitor, if registered
		if p.secretManager.IsRouteRegistered(route.Namespace, route.Name) {
			if err := p.secretManager.UnregisterRoute(route.Namespace, route.Name); err != nil {
				log.Error(err, "failed to unregister route")
				return err
			}
		}
	default:
		return fmt.Errorf("invalid eventType %v", eventType)
	}

	// call next plugin
	return p.plugin.HandleRoute(eventType, route)
}

// validateAndRegister validates the route's externalCertificate configuration and registers it with the secret manager.
// It also updates the in-memory TLS certificate and key after reading from secret informer's cache.
func (p *RouteSecretManager) validateAndRegister(route *routev1.Route) error {
	fldPath := field.NewPath("spec").Child("tls").Child("externalCertificate")
	// validate
	if err := routeapihelpers.ValidateTLSExternalCertificate(route, fldPath, p.sarClient, p.secretsGetter).ToAggregate(); err != nil {
		log.Error(err, "skipping route due to invalid externalCertificate configuration", "namespace", route.Namespace, "route", route.Name)
		p.recorder.RecordRouteRejection(route, "ExternalCertificateValidationFailed", err.Error())
		p.plugin.HandleRoute(watch.Deleted, route)
		return err
	}

	// register route with secretManager
	secreth := p.generateSecretHandler(route)
	if err := p.secretManager.RegisterRoute(context.TODO(), route.Namespace, route.Name, getReferencedSecret(route), secreth); err != nil {
		log.Error(err, "failed to register route")
		return err
	}
	// read referenced secret
	secret, err := p.secretManager.GetSecret(context.TODO(), route.Namespace, route.Name)
	if err != nil {
		log.Error(err, "failed to read referenced secret")
		return err
	}
	// update tls.Certificate and tls.Key
	// since externalCertificate will not contain CACertificate, tls.CACertificate won't be updated.
	// NOTE: this will be in-memory change and won't update actual route resource.
	route.Spec.TLS.Certificate = string(secret.Data["tls.crt"])
	route.Spec.TLS.Key = string(secret.Data["tls.key"])

	return nil
}

// generateSecretHandler creates ResourceEventHandlerFuncs to handle Add, Update, and Delete events on secrets.
// AddFunc: Invoked when a new secret is added. It logs the addition of the secret.
// UpdateFunc: Invoked when an existing secret is updated. It performs validation of the route's external certificate configuration.
// If the validation fails, it records the route rejection, and triggers the deletion of the route by calling the HandleRoute method with a watch.Deleted event.
// If the validation succeeds, it updates the route's TLS certificate and key with the new secret data and calls the next plugin's HandleRoute method with a watch.Modified event, and then the next plugin's Commit() method.
// DeleteFunc: Invoked when the secret is deleted. It unregisters the associated route, records the route rejection, and triggers the deletion of the route by calling the HandleRoute method with a watch.Deleted event.
func (p *RouteSecretManager) generateSecretHandler(route *routev1.Route) cache.ResourceEventHandlerFuncs {
	// secret handler
	secreth := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret := obj.(*kapi.Secret)
			log.V(4).Info("secret added for route", "namespace", route.Namespace, "secret", secret.Name, "route", route.Name)
			// Do nothing for add event
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			secretOld := old.(*kapi.Secret)
			secretNew := new.(*kapi.Secret)
			log.V(4).Info("secret updated for route", "namespace", route.Namespace, "secret", secretNew.Name, "old-version", secretOld.ResourceVersion, "new-version", secretNew.ResourceVersion, "route", route.Name)

			// re-validate
			fldPath := field.NewPath("spec").Child("tls").Child("externalCertificate")
			if err := routeapihelpers.ValidateTLSExternalCertificate(route, fldPath, p.sarClient, p.secretsGetter).ToAggregate(); err != nil {
				log.Error(err, "skipping route due to invalid externalCertificate configuration", "namespace", route.Namespace, "route", route.Name)
				p.recorder.RecordRouteRejection(route, "ExternalCertificateValidationFailed", err.Error())
				p.plugin.HandleRoute(watch.Deleted, route)
				return
			}

			// read referenced secret (updated data)
			secret, err := p.secretManager.GetSecret(context.TODO(), route.Namespace, route.Name)
			if err != nil {
				log.Error(err, "failed to read referenced secret")
				p.recorder.RecordRouteRejection(route, "ExternalCertificateReadFailed", err.Error())
				p.plugin.HandleRoute(watch.Deleted, route)
				return
			}

			// update tls.Certificate and tls.Key
			route.Spec.TLS.Certificate = string(secret.Data["tls.crt"])
			route.Spec.TLS.Key = string(secret.Data["tls.key"])

			// call the next plugin with watch.Modified
			p.plugin.HandleRoute(watch.Modified, route)
			// commit the changes
			p.plugin.Commit()
		},
		DeleteFunc: func(obj interface{}) {
			secret := obj.(*kapi.Secret)
			msg := fmt.Sprintf("secret %s deleted for route %s/%s", secret.Name, route.Namespace, route.Name)
			log.V(4).Info(msg)

			// unregister associated secret monitor
			if err := p.secretManager.UnregisterRoute(route.Namespace, route.Name); err != nil {
				log.Error(err, "failed to unregister route")
			}

			p.recorder.RecordRouteRejection(route, "ExternalCertificateSecretDeleted", msg)
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
	log.V(10).Info("referenced externalCertificate", "secret", secretName)
	return secretName
}
