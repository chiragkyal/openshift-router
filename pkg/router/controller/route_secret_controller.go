package controller

import (
	"context"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/route/secretmanager"
	"github.com/openshift/router/pkg/router"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type RouteSecretController struct {
	// plugin is the next plugin in the chain.
	plugin router.Plugin
	// recorder is an interface for indicating route rejections.
	recorder RejectionRecorder

	secretManager *secretmanager.Manager
	// queue         workqueue.RateLimitingInterface
}

func NewRouteSecretController(plugin router.Plugin, recorder RejectionRecorder, secretManager *secretmanager.Manager) *RouteSecretController {
	return &RouteSecretController{
		plugin:        plugin,
		recorder:      recorder,
		secretManager: secretManager,
		// queue:         queue,
	}
}

func (c *RouteSecretController) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	switch eventType {
	case watch.Added:
		if hasExternalCertificate(route) {
			err := c.registerRouteWithSecretManager(route)
			if err != nil {
				klog.Error("failed to register route")
				return err
			}
		}
	case watch.Modified:
		// TODO: Since we are not sure
		// 1. whether the old route was using externalCertificate or not [if it was using secret informer must be removed]
		// 2. whether the externalCertificate (secretName) was updated or not

		// always remove the old watch [without checking hasExternalCertificate()], and create a new secret watch
		// even if the referenced secretName is same

		// need to ignore error for reason 1
		// Solution : add new method : IsRouteRegistered()
		_ = c.secretManager.UnregisterRoute(route.Namespace, route.Name)

		if hasExternalCertificate(route) {
			err := c.registerRouteWithSecretManager(route)
			if err != nil {
				klog.Error("failed to register route")
				return err
			}
		}

	case watch.Deleted:
		if hasExternalCertificate(route) { // instead use IsRouteRegistered()
			err := c.secretManager.UnregisterRoute(route.Namespace, route.Name)
			if err != nil {
				klog.Error(err)
				return err
			}
		}
	default:
		klog.Error("invalid eventType", eventType)

	}
	// TODO: should be pass to next handler here, or after queue is done will processing ?
	return c.plugin.HandleRoute(eventType, route)
}

func (c *RouteSecretController) registerRouteWithSecretManager(route *routev1.Route) error {
	secreth := c.generateSecretHandler(route)
	c.secretManager.WithSecretHandler(secreth)
	return c.secretManager.RegisterRoute(context.Background(), route.Namespace, route.Name, getReferencedSecret(route))
}

func (c *RouteSecretController) generateSecretHandler(route *routev1.Route) cache.ResourceEventHandlerFuncs {
	// secret handler
	secreth := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret := obj.(*kapi.Secret)
			klog.Info("Secret added ", " secret.Name ", secret.Name, " for ", route.Namespace+"/"+route.Name)
			// Don't call c.plugin.HandleRoute(watch.Modified, route), because it's caller will anyway call it, avoid twice calling
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			secretOld := old.(*kapi.Secret)
			secretNew := new.(*kapi.Secret)
			klog.Info("Secret updated ", "old ", secretOld.ResourceVersion, " new ", secretNew.ResourceVersion, " For ", route.Namespace+"/"+route.Name)
			// next plugin will update the secret (certificate) contents
			c.plugin.HandleRoute(watch.Modified, route)
		},
		DeleteFunc: func(obj interface{}) {
			secret := obj.(*kapi.Secret)
			klog.Info("Secret deleted ", " secret.Name ", secret.Name, " for ", route.Namespace+"/"+route.Name)
			// TODO: what should be the behaviour when secret is removed?
			// ValidateRoute() will not trigger until route is updated

			// next plugin should error out while retrieving the secret
			c.plugin.HandleRoute(watch.Modified, route)
		},
	}
	return secreth
}

func hasExternalCertificate(route *routev1.Route) bool {
	tls := route.Spec.TLS.DeepCopy()
	if tls.ExternalCertificate != nil && len(tls.ExternalCertificate.Name) > 0 {
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

func (c *RouteSecretController) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	return c.plugin.HandleNode(eventType, node)
}

func (c *RouteSecretController) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	return c.plugin.HandleEndpoints(eventType, endpoints)
}

func (c *RouteSecretController) HandleNamespaces(namespaces sets.String) error {
	return c.plugin.HandleNamespaces(namespaces)
}

func (c *RouteSecretController) Commit() error {
	return c.plugin.Commit()
}
