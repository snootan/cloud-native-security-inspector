package consumers

import (
	"context"
	api "github.com/vmware-tanzu/cloud-native-security-inspector/src/api/v1alpha1"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/cspauth"
	openapi "github.com/vmware-tanzu/cloud-native-security-inspector/src/pkg/data/consumers/governor/go-client"
	v1 "k8s.io/api/core/v1"
	"os"
	"testing"
)

var (
	mockClient   *openapi.APIClient
	clusterID    = "testingId"
	namespace    = "testingNamespace"
	name         = "name"
	image        = "image"
	imageID      = "imageId"
	replicaCount = 2
)

const (
	testHost   = "clusterapi.swagger.io:80"
	testScheme = "http"
)

func TestMain(m *testing.M) {
	cfg := openapi.NewConfiguration()
	cfg.AddDefaultHeader("testheader", "testvalue")
	cfg.Host = testHost
	cfg.Scheme = testScheme
	mockClient = openapi.NewAPIClient(cfg)
	retCode := m.Run()
	os.Exit(retCode)
}

func TestSendReportToGovernorSuccess(t *testing.T) {
	actualApi := mockClient.ClustersApi
	mockApi := NewMockClustersApi()
	mockClient.ClustersApi = mockApi

	g := GovernorExporter{
		Report: &api.AssessmentReport{
			Spec: api.AssessmentReportSpec{NamespaceAssessments: []*api.NamespaceAssessment{{Namespace: v1.LocalObjectReference{
				Name: namespace,
			},
				WorkloadAssessments: []*api.WorkloadAssessment{{Workload: api.Workload{Replicas: int32(replicaCount),
					Pods: []*api.Pod{{Containers: []*api.Container{{
						Name:    name,
						Image:   image,
						ImageID: imageID,
					}}}}}}}}}}},
		ClusterID: clusterID,
		ApiClient: mockClient,
	}
	provider := cspauth.NewMockProvider()
	provider.Token = "dummy-token"
	ctx := context.WithValue(context.Background(), "cspProvider", provider)
	errFromSendReportToGovernor := g.SendReportToGovernor(ctx)
	if errFromSendReportToGovernor != nil {
		t.Fatalf("Error while updating telemetry data of workloads in cluster: %v", errFromSendReportToGovernor)
	}
	mockClient.ClustersApi = actualApi

}

func TestSendReportToGovernorNoProvider_Negative(t *testing.T) {
	actualApi := mockClient.ClustersApi
	mockApi := NewMockClustersApi()
	mockClient.ClustersApi = mockApi

	g := GovernorExporter{
		Report: &api.AssessmentReport{
			Spec: api.AssessmentReportSpec{NamespaceAssessments: []*api.NamespaceAssessment{{Namespace: v1.LocalObjectReference{
				Name: namespace,
			},
				WorkloadAssessments: []*api.WorkloadAssessment{{Workload: api.Workload{Replicas: int32(replicaCount),
					Pods: []*api.Pod{{Containers: []*api.Container{{
						Name:    name,
						Image:   image,
						ImageID: imageID,
					}}}}}}}}}}},
		ClusterID: clusterID,
		ApiClient: mockClient,
	}
	errFromSendReportToGovernor := g.SendReportToGovernor(context.Background())
	if errFromSendReportToGovernor == nil {
		t.Fatalf("Call to SendReportToGovernor should have failed!!!")
	}
	if errFromSendReportToGovernor.Error() != "CSP Provider not found!" {
		t.Fatalf("Call to SendReportToGovernor should have failed with error CSP Provider not found!")
	}
	mockClient.ClustersApi = actualApi
}

func TestSendReportToGovernorNoAccessToken_Negative(t *testing.T) {
	actualApi := mockClient.ClustersApi
	mockApi := NewMockClustersApi()
	mockClient.ClustersApi = mockApi

	g := GovernorExporter{
		Report: &api.AssessmentReport{
			Spec: api.AssessmentReportSpec{NamespaceAssessments: []*api.NamespaceAssessment{{Namespace: v1.LocalObjectReference{
				Name: namespace,
			},
				WorkloadAssessments: []*api.WorkloadAssessment{{Workload: api.Workload{Replicas: int32(replicaCount),
					Pods: []*api.Pod{{Containers: []*api.Container{{
						Name:    name,
						Image:   image,
						ImageID: imageID,
					}}}}}}}}}}},
		ClusterID: clusterID,
		ApiClient: mockClient,
	}
	provider := cspauth.NewMockProvider()
	provider.Token = ""
	ctx := context.WithValue(context.Background(), "cspProvider", provider)
	errFromSendReportToGovernor := g.SendReportToGovernor(ctx)
	if errFromSendReportToGovernor == nil {
		t.Fatalf("SendReportToGovernor should have failed! %v", errFromSendReportToGovernor)
	}

	if errFromSendReportToGovernor.Error() != "No token available!" {
		t.Fatalf("SendReportToGovernor should have failed with No token available! %v", errFromSendReportToGovernor)
	}

	mockClient.ClustersApi = actualApi

}
