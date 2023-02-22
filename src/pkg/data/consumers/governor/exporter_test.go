package consumers

import (
	"context"
	openapi "gitlab.eng.vmware.com/vac/catalog-governor/api-specs/catalog-governor-service-rest/go-client"
	"os"
	"testing"
)

var client *openapi.APIClient

var clusterID = "testingId"

const (
	testHost   = "clusterapi.swagger.io:80"
	testScheme = "http"
)

func TestMain(m *testing.M) {
	cfg := openapi.NewConfiguration()
	cfg.AddDefaultHeader("testheader", "testvalue")
	cfg.Host = testHost
	cfg.Scheme = testScheme
	client = openapi.NewAPIClient(cfg)
	retCode := m.Run()
	os.Exit(retCode)
}

func TestUpdateTelemetry(t *testing.T) {
	updateTelemetryData := openapi.KubernetesTelemetryRequest{Workloads: []openapi.KubernetesWorkload{{Namespace: "namespace",
		Name: "name", Kind: "testKind", Replicas: 2,
		Containers: []openapi.Container{{
			Name:    "testingNgnix",
			Image:   "image",
			ImageId: "imageId"}}}}}

	r, err := client.ClustersApi.UpdateTelemetry(context.Background(), clusterID).
		KubernetesTelemetryRequest(updateTelemetryData).Execute()

	if err != nil {
		t.Fatalf("Error while updating telemetry data of workloads in cluster: %v", err)
	}
	if r.StatusCode != 200 {
		t.Log(r)
	}
}

func TestClusterApiMock(t *testing.T) {
	actualApi := client.ClustersApi
	mockApi := NewMockClustersApi()
	client.ClustersApi = mockApi
	TestUpdateTelemetry(t)
	client.ClustersApi = actualApi
}
