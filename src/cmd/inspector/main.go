// Copyright 2022 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/api/v1alpha1"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	cspauth "github.com/vmware-tanzu/cloud-native-security-inspector/src/pkg/data/consumers/governor/httpauth"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/pkg/inspection"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	secret "k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	scheme  = runtime.NewScheme()
	rootCtx = context.Background()
)

const (
	cspSecretNamespace = "cnsi-system"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch;create;update;patch;delete

func main() {
	var policy string

	flag.StringVar(&policy, "policy", "", "name of the inspection policy")
	flag.Parse()
	log.Infof("policy name %s", policy)
	log.Info("inspector scanning")

	k8sClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{
		Scheme: scheme,
	})

	if err != nil {
		log.Error(err, "unable to create k8s client")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(rootCtx)
	defer cancel()

	// Get the policy CR details.
	inspectionPolicy := &v1alpha1.InspectionPolicy{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: policy}, inspectionPolicy); err != nil {
		log.Error(err, "unable to retrieve the specified inspection policy")
		os.Exit(1)
	}

	if inspectionPolicy.Spec.Inspection.Assessment.Governor.Enabled {
		err, cspApiToken := getCSPTokenFromSecret(ctx, cspSecretNamespace, inspectionPolicy.Spec.Inspection.Assessment.Governor.CspSecretName)
		if err != nil {
			log.Error(err, " unable to fetch CSP api-token, this is mandatory for connecting Governor back end!")
			os.Exit(1)
		}

		cspProvider, err := cspauth.NewCSPAuth(ctx, cspApiToken)
		if err != nil {
			log.Error(err, " unable to establish connection with CSP, this is mandatory for connecting Governor back end!")
			os.Exit(1)
		}
		ctx = context.WithValue(ctx, "cspProvider", cspProvider)
	}

	runner := inspection.NewController().
		WithScheme(scheme).
		WithK8sClient(k8sClient).
		CTRL()

	if err := runner.Run(ctx, inspectionPolicy); err != nil {
		log.Error(err, "controller run")
		os.Exit(1)
	}
}

func getCSPTokenFromSecret(ctx context.Context, ns string, secretName string) (error, string) {
	config, err := secret.NewForConfig(ctrl.GetConfigOrDie())
	getSecret, err := config.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		log.Error(err, "Failed to fetch secret")
		return err, ""
	}
	cspApiToken := string(getSecret.Data["accessSecret"])
	return err, cspApiToken
}
