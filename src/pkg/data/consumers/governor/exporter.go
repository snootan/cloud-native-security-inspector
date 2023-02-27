package consumers

import (
	"context"
	"errors"
	"fmt"
	api "github.com/vmware-tanzu/cloud-native-security-inspector/src/api/v1alpha1"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/cspauth"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	openapi "github.com/vmware-tanzu/cloud-native-security-inspector/src/pkg/data/consumers/governor/go-client"
	"net/http"
)

type GovernorExporter struct {
	Report    *api.AssessmentReport
	ClusterID string
	ApiClient *openapi.APIClient
}

// SendReportToGovernor is used to send report to governor url http end point.
func (g GovernorExporter) SendReportToGovernor(ctx context.Context) error {
	// Get governor api request model from assessment report.
	kubernetesCluster := g.getGovernorAPIPayload()

	log.Info("Payload data for governor:")
	log.Info(kubernetesCluster)
	provider, ok := ctx.Value("cspProvider").(cspauth.Provider)
	if !ok {
		log.Error(" CSP Provider not found!")
	}

	governorAccessToken, err := provider.GetBearerToken(ctx)
	if err != nil {
		log.Error("Error while retrieving access token !")
		return err
	}

	ctx = context.WithValue(ctx, openapi.ContextAccessToken, governorAccessToken)

	apiSaveClusterRequest := g.ApiClient.ClustersApi.UpdateTelemetry(ctx, g.ClusterID).KubernetesTelemetryRequest(kubernetesCluster)

	// Call api cluster to send telemetry data and get response.
	response, err := g.ApiClient.ClustersApi.UpdateTelemetryExecute(apiSaveClusterRequest)
	if err != nil {
		log.Errorf("Governor api response error: %v", err)
		return err
	}

	log.Info("successful called governor api")
	log.Info(response)

	if response.StatusCode != http.StatusNoContent {
		log.Errorf("Governor api response status: %v", response.StatusCode)
		return errors.New(fmt.Sprintf("Governor api response status: %s", response.Status))
	}

	return nil
}

// getGovernorAPIPayload is used to map assessment report to client model.
func (g GovernorExporter) getGovernorAPIPayload() openapi.KubernetesTelemetryRequest {
	kubernetesCluster := openapi.NewKubernetesTelemetryRequestWithDefaults()
	kubernetesCluster.Workloads = make([]openapi.KubernetesWorkload, 0)
	for _, nsa := range g.Report.Spec.NamespaceAssessments {
		for _, workloadAssessment := range nsa.WorkloadAssessments {
			kubernetesWorkloads := openapi.NewKubernetesWorkloadWithDefaults()
			kubernetesWorkloads.Name = workloadAssessment.Workload.Name
			kubernetesWorkloads.Kind = workloadAssessment.Workload.Kind
			kubernetesWorkloads.Namespace = nsa.Namespace.Name
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
