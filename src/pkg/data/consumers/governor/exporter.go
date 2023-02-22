package consumers

import (
	"context"
	"errors"
	"fmt"
	api "github.com/vmware-tanzu/cloud-native-security-inspector/src/api/v1alpha1"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	openapi "gitlab.eng.vmware.com/vac/catalog-governor/api-specs/catalog-governor-service-rest/go-client"
	"net/http"
)

type GovernorExporter struct {
	Report    *api.AssessmentReport
	ClusterID string
	ApiURL    string
	ApiToken  string
}

// SendReportToGovernor is used to send report to governor url http end point.
func (g GovernorExporter) SendReportToGovernor() error {
	// Get governor api request model from assessment report.
	kubernetesCluster := getGovernorAPIPayload(*g.Report)

	// Create api client to governor api.
	config := openapi.NewConfiguration()

	// Appending api URL in configuration.
	config.Servers = openapi.ServerConfigurations{{
		URL: g.ApiURL,
	}}
	
	apiClient := openapi.NewAPIClient(config)
	apiSaveClusterRequest := apiClient.ClustersApi.UpdateTelemetry(context.Background(), g.ClusterID).KubernetesTelemetryRequest(kubernetesCluster)

	// Call api cluster to send telemetry data and get response.
	response, err := apiClient.ClustersApi.UpdateTelemetryExecute(apiSaveClusterRequest)
	if err != nil {
		log.Errorf("Governor api response error: %v", err)
		return err
	}
	if response.StatusCode != http.StatusOK {
		log.Errorf("Governor api response status: %v", response.StatusCode)
		return errors.New(fmt.Sprintf("Governor api response status: %s", response.Status))
	}

	return nil
}

// getGovernorAPIPayload is used to map assessment report to client model.
func getGovernorAPIPayload(doc api.AssessmentReport) openapi.KubernetesTelemetryRequest {
	kubernetesCluster := openapi.NewKubernetesTelemetryRequestWithDefaults()
	for _, nsa := range doc.Spec.NamespaceAssessments {
		for _, workloadAssessment := range nsa.WorkloadAssessments {
			kubernetesWorkloads := openapi.NewKubernetesWorkloadWithDefaults()
			kubernetesWorkloads.Name = workloadAssessment.Workload.Name
			kubernetesWorkloads.Kind = workloadAssessment.Workload.Kind
			if nsa.Namespace.Name != "" {
				kubernetesWorkloads.Namespace = nsa.Namespace.Name
			}
			kubernetesWorkloads.Replicas = workloadAssessment.Workload.Replicas
			for _, pod := range workloadAssessment.Workload.Pods {
				containerData := openapi.NewContainerWithDefaults()
				for _, container := range pod.Containers {
					containerData.Name = container.Name
					containerData.ImageId = container.ImageID
					containerData.Image = container.Image
					kubernetesWorkloads.Containers = append(kubernetesWorkloads.Containers, *containerData)
				}
			}
			kubernetesCluster.Workloads = append(kubernetesCluster.Workloads, *kubernetesWorkloads)
		}
	}
	return *kubernetesCluster
}
