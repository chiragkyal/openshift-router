package controller

import (
	"errors"
	"fmt"
	"time"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/route/secretmanager"
	"github.com/openshift/router/pkg/router"
	kapi "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type RouteSecretController struct {
	// plugin is the next plugin in the chain.
	plugin router.Plugin
	// recorder is an interface for indicating route rejections.
	recorder RejectionRecorder

	secretManager *secretmanager.Manager

	informer cache.SharedIndexInformer
	indexer  cache.Indexer
	queue    workqueue.RateLimitingInterface
}

type queueEventKey struct {
	eventType watch.EventType
	route     *routev1.Route
	// secretManager *secretmanager.Manager
}

func newQueueEventKey(eventType watch.EventType, route *routev1.Route, secretManager *secretmanager.Manager) *queueEventKey {
	return &queueEventKey{
		eventType: eventType,
		route:     route,
		// secretManager: secretManager,
	}
}

func NewRouteSecretController(plugin router.Plugin, recorder RejectionRecorder, secretManager *secretmanager.Manager, informer cache.SharedIndexInformer, queue workqueue.RateLimitingInterface) *RouteSecretController {
	return &RouteSecretController{
		plugin:        plugin,
		recorder:      recorder,
		secretManager: secretManager,
		informer:      informer,
		indexer:       informer.GetIndexer(),
		queue:         queue,
	}
}

// Run begins watching and syncing.
func (c *RouteSecretController) Run(stopCh chan struct{}) error {
	defer utilruntime.HandleCrash()

	if c.informer == nil {
		return errors.New("RouteSecretController: missing informer")
	}

	// TODO: Check this should be called after the router_controller starts the informer
	if c.informer.IsStopped() {
		klog.Info("RouteSecretController: restarting informers")
		go c.informer.Run(stopCh)
	}

	// Add Event Handlers, informer must be can running
	if err := c.registerSharedInformerEventHandlers(); err != nil {
		return err
	}

	// Let the workers stop when we are done
	defer c.queue.ShutDown()
	klog.Info("Starting RouteSecretController")

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for caches to sync")
	}

	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh

	klog.Infof("Stopping RouteSecretController")
	return nil
}

func (c *RouteSecretController) runWorker() {
	for c.processNextItem() {
	}
}
func (c *RouteSecretController) registerSharedInformerEventHandlers() error {

	// Add Event Handler for Route
	_, err := c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			route := obj.(*routev1.Route)
			klog.Info("RouteSecretController: Add event ", "route.Name ", route.Name)
			c.queue.Add(newQueueEventKey(watch.Added, route, c.secretManager))
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			oldRoute := old.(*routev1.Route)
			newRoute := new.(*routev1.Route)

			if getReferenceSecret(oldRoute) != getReferenceSecret(newRoute) {
				klog.Info("RouteSecretController: Update event ", "old ", oldRoute.ResourceVersion, " new ", newRoute.ResourceVersion)
				// remove old watch
				c.queue.Add(newQueueEventKey(watch.Deleted, oldRoute, c.secretManager))
				// create new watch
				c.queue.Add(newQueueEventKey(watch.Added, newRoute, c.secretManager))
			}
		},
		DeleteFunc: func(obj interface{}) {
			route := obj.(*routev1.Route)
			klog.Info("RouteSecretController: Delete event ", "route.Name ", route.Name)

			// when route is deleted, remove associated secret watcher
			c.queue.Add(newQueueEventKey(watch.Deleted, route, c.secretManager))
		},
	})

	if err != nil {
		return fmt.Errorf("failed to register informer event handlers: %w", err)
	}
	return nil
}

// Implement me
func (c *RouteSecretController) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	return c.plugin.HandleRoute(eventType, route)
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

func getReferenceSecret(route *routev1.Route) string {
	secretName := route.Spec.TLS.ExternalCertificate.Name
	klog.Info("Referenced secretName: ", secretName)
	return secretName
}
