package consumers

import (
	"context"
	"errors"
	api "github.com/vmware-tanzu/cloud-native-security-inspector/src/api/v1alpha1"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/cspauth"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	openapi "gitlab.eng.vmware.com/vac/catalog-governor/api-specs/catalog-governor-service-rest/go-client"
	"net/http"
)

type GovernorExporter struct {
	Report    *api.AssessmentReport
	ClusterID string
	ApiURL    string
}

// SendReportToGovernor is used to send report to governor url http end point.
func (g GovernorExporter) SendReportToGovernor(ctx context.Context) error {
	// Get api request model from assessment report.
	kubernetesCluster := getAPIRequest(*g.Report)

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

	// Create api client to governor api.
	apiClient := openapi.NewAPIClient(openapi.NewConfiguration())
	apiSaveClusterRequest := apiClient.ClustersApi.UpdateTelemetry(ctx, g.ClusterID)

	// Call api cluster to send telemetry data and get response.
	response, err := apiSaveClusterRequest.KubernetesTelemetryRequest(kubernetesCluster).Execute()
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return errors.New(response.Status)
	}

	return nil
}

// getAPIRequest is used to map assessment report to client model.
func getAPIRequest(doc api.AssessmentReport) openapi.KubernetesTelemetryRequest {
	kubernetesCluster := openapi.NewKubernetesTelemetryRequestWithDefaults()
	for _, nsa := range doc.Spec.NamespaceAssessments {
		for _, workloadAssessment := range nsa.WorkloadAssessments {
			kubernetesWorkloads := openapi.NewKubernetesWorkloadWithDefaults()
			kubernetesWorkloads.Name = workloadAssessment.Workload.Name
			kubernetesWorkloads.Kind = workloadAssessment.Workload.Kind
			kubernetesWorkloads.Namespace = nsa.Namespace.Name
			kubernetesWorkloads.Replicas = *workloadAssessment.Workload.Replicas.Spec.Replicas
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
