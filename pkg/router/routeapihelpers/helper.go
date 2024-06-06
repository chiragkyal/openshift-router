package routeapihelpers

import (
	"context"
	"strings"

	routev1 "github.com/openshift/api/route/v1"
	apierros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

func RouteLessThan(route1, route2 *routev1.Route) bool {
	if route1.CreationTimestamp.Before(&route2.CreationTimestamp) {
		return true
	}

	if route2.CreationTimestamp.Before(&route1.CreationTimestamp) {
		return false
	}

	return route1.UID < route2.UID
}

// GetDomainForHost returns the domain for the specified host.
// Note for top level domains, this will return an empty string.
func GetDomainForHost(host string) string {
	if idx := strings.IndexRune(host, '.'); idx > -1 {
		return host[idx+1:]
	}

	return ""
}

// EnsureFinalizer adds a finalizer to a secret if it doesn't already exist. No-op otherwise.
// It re-tries on conflicts.
// NOTE: New finalizer can not be added if the secret's deletionTimestamp is set, only existing finalizers can be removed. Ref: https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/
func EnsureFinalizer(ctx context.Context, secretClient corev1client.SecretsGetter, namespace, secretName, finalizerName string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		secret, err := secretClient.Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		// add finalizer, if not present
		if finalizers := sets.New(secret.Finalizers...); !finalizers.Has(finalizerName) {
			finalizers.Insert(finalizerName)
			secret.Finalizers = sets.List(finalizers)

			// Update the Secret
			_, err = secretClient.Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
			klog.V(2).Infof("Added finalizer %s to secret %s/%s : %v", finalizerName, namespace, secretName, secret.Finalizers)
		}
		return nil
	})
}

// RemoveFinalizer removes a finalizer from a secret, if it is present. No-op otherwise.
// It re-tries on conflicts.
func RemoveFinalizer(ctx context.Context, secretClient corev1client.SecretsGetter, namespace, secretName, finalizerName string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		secret, err := secretClient.Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			if apierros.IsNotFound(err) {
				return nil
			}
			return err
		}

		// remove finalizer, if present
		if finalizers := sets.New(secret.Finalizers...); finalizers.Has(finalizerName) {
			delete(finalizers, finalizerName)
			secret.Finalizers = sets.List(finalizers)

			// Update the Secret
			_, err = secretClient.Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
			klog.V(2).Infof("Removed finalizer %s from secret %s/%s : %v", finalizerName, namespace, secretName, secret.Finalizers)
		}
		return nil
	})
}
