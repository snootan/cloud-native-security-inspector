package consumers

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"context"
	api "github.com/vmware-tanzu/cloud-native-security-inspector/src/api/v1alpha1"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/cspauth"
	openapi "github.com/vmware-tanzu/cloud-native-security-inspector/src/pkg/data/consumers/governor/go-client"
	v1 "k8s.io/api/core/v1"
	"net/http"
	"testing"
)

var (
	mockClient   *openapi.APIClient
	clusterID       = "testingId"
	apiToken        = "apiToken"
	namespace    = "testingNamespace"
	name         = "name"
	image        = "image"
	imageID      = "imageId"
	replicaCount = 2
	testHeader      = "testHeader"
	testHeaderValue = "testHeaderValue"
)

const (
	testHost       = "clusterapi.swagger.io:80"
	testInvalidURL = "asdfdasfasv.sadfdsf"
	testScheme     = "http"
)

func TestSendReportToGovernor(t *testing.T) {
	testDataStruct := []struct {
		testCaseDescription string
		testHost            string
		testHeader          string
		testHeaderValue     string
		testReportData      *api.AssessmentReport
		testClusterID       string
		testAPIToken        string
		testStatusCode      int
	}{
		{
			testCaseDescription: "Success: Happy flow end to end.",
			testHost:            testHost,
			testHeader:          testHeader,
			testHeaderValue:     "testvalue",
			testReportData: &api.AssessmentReport{
				Spec: api.AssessmentReportSpec{NamespaceAssessments: []*api.NamespaceAssessment{{Namespace: v1.LocalObjectReference{
					Name: namespace,
				},
					WorkloadAssessments: []*api.WorkloadAssessment{{Workload: api.Workload{Replicas: int32(replicaCount),
						Pods: []*api.Pod{{Containers: []*api.Container{{
							Name:    name,
							Image:   image,
							ImageID: imageID,
						}}}}}}}}}}},
			testClusterID:  clusterID,
			testAPIToken:   apiToken,
			testStatusCode: http.StatusNoContent,
		},
		{
			testCaseDescription: "Success: Empty payload, successful case",
			testHost:            testHost,
			testHeader:          testHeader,
			testHeaderValue:     testHeaderValue,
			testReportData:      &api.AssessmentReport{},
			testClusterID:       clusterID,
			testAPIToken:        apiToken,
			testStatusCode:      http.StatusNoContent,
		},
		{
			testCaseDescription: "Failure: Error from API call.",
			testHost:            testHost,
			testHeader:          testHeader,
			testHeaderValue:     testHeaderValue,
			testReportData:      &api.AssessmentReport{},
			testClusterID:       clusterID,
			testAPIToken:        apiToken,
			testStatusCode:      http.StatusInternalServerError,
		},
		{
			testCaseDescription: "Failure Invalid URL: Error from api.",
			testHost:            testInvalidURL,
			testHeader:          testHeader,
			testHeaderValue:     testHeaderValue,
			testReportData:      &api.AssessmentReport{},
			testClusterID:       clusterID,
			testAPIToken:        apiToken,
			testStatusCode:      http.StatusBadRequest,
		},
		{
			testCaseDescription: "Failure: Timeout to receive response from api.",
			testHost:            testHost,
			testHeader:          testHeader,
			testHeaderValue:     testHeaderValue,
			testReportData:      &api.AssessmentReport{},
			testClusterID:       clusterID,
			testAPIToken:        apiToken,
			testStatusCode:      http.StatusRequestTimeout,
		},
	}

	for _, tt := range testDataStruct {
		t.Run(tt.testCaseDescription, func(t *testing.T) {
			var clusterClient *openapi.APIClient
			mockConfig := openapi.NewConfiguration()
			mockConfig.AddDefaultHeader(tt.testHeader, tt.testHeaderValue)
			mockConfig.Host = tt.testHost
			mockConfig.Scheme = testScheme
			clusterClient = openapi.NewAPIClient(mockConfig)

			g := GovernorExporter{
				Report:    tt.testReportData,
				ApiClient: clusterClient,
				ClusterID: tt.testClusterID,
			}
			mockAPIClient := new(ClustersApi)

			response := openapi.ApiUpdateTelemetryRequest{
				ApiService: mockAPIClient,
			}
			clusterClient.ClustersApi = mockAPIClient
			response.KubernetesTelemetryRequest(g.getGovernorAPIPayload())
			mockAPIClient.On("UpdateTelemetry", mock.Anything, mock.Anything).Return(response)
			mockAPIClient.On("UpdateTelemetryExecute", mock.Anything).Return(&http.Response{
				StatusCode: tt.testStatusCode,
			}, nil)

			errFromSendReportToGovernor := g.SendReportToGovernor(context.Background())
			if tt.testStatusCode != http.StatusNoContent {
				assert.Error(t, errFromSendReportToGovernor)
			} else {
				assert.NoError(t, errFromSendReportToGovernor)
			}
		})
	}
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
