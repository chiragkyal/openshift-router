package controller

import (
	routev1 "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type RouteReSync interface {
	UpdateRoot(root *RouterController)
	ReSync(eventType watch.EventType, route *routev1.Route)
}

type routeReSync struct {
	rootPlugin *RouterController
}

func NewRouteReSync() RouteReSync {
	return &routeReSync{}
}

func (r *routeReSync) UpdateRoot(root *RouterController) {
	r.rootPlugin = root
}

func (r *routeReSync) ReSync(eventType watch.EventType, route *routev1.Route) {
	if r.rootPlugin != nil {
		r.rootPlugin.HandleRoute(eventType, route)
	}
}
