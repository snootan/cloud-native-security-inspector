package consumers

import (
	"context"
	"errors"
	api "github.com/vmware-tanzu/cloud-native-security-inspector/src/api/v1alpha1"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	openapi "gitlab.eng.vmware.com/vac/catalog-governor/api-specs/catalog-governor-service-rest/go-client"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
)

type GovernorExporter struct {
	Report    *api.AssessmentReport
	ClusterID string
	ApiURL    string
	ApiToken  string
}

// SendReportToGovernor is used to send report to governor url http end point.
func (g GovernorExporter) SendReportToGovernor() error {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if _, ok := os.LookupEnv("HOME"); !ok {
		u, err := user.Current()
		if err != nil {
			log.Error(err, "user error")
		}
		loadingRules.Precedence = append(loadingRules.Precedence, filepath.Join(u.HomeDir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName))
	}

	// Calling to get cluster name on the basis of precedence path of config.
	clusterName := loadConfigWithContext(loadingRules)

	// Get api request model from assessment report.
	kubernetesCluster := getAPIRequest(*g.Report)
	kubernetesCluster.Name = clusterName

	// Create api client to governor api.
	apiClient := openapi.NewAPIClient(openapi.NewConfiguration())
	apiSaveClusterRequest := apiClient.ClustersApi.SaveCluster(context.Background(), g.ClusterID)

	// Call api cluster to send telemetry data and get response.
	response, err := apiSaveClusterRequest.KubernetesClusterRequest(kubernetesCluster).Execute()
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return errors.New(response.Status)
	}

	return nil
}

// getAPIRequest is used to map assessment report to client model.
func getAPIRequest(doc api.AssessmentReport) openapi.KubernetesClusterRequest {
	kubernetesCluster := openapi.NewKubernetesClusterRequestWithDefaults()
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

// loadConfigWithContext is used get current cluster name
func loadConfigWithContext(loader clientcmd.ClientConfigLoader) string {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loader,
		&clientcmd.ConfigOverrides{
			CurrentContext: "",
		}).RawConfig()
	if err != nil {
		log.Error(err)
	}

	return config.CurrentContext
}
