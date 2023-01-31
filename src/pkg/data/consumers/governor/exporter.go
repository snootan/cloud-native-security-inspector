package consumers

import (
	"context"
	"errors"
	"github.com/google/uuid"
	api "github.com/vmware-tanzu/cloud-native-security-inspector/src/api/v1alpha1"
	"github.com/vmware-tanzu/cloud-native-security-inspector/src/lib/log"
	openapi "github.com/vmware-tanzu/cloud-native-security-inspector/src/pkg/data/consumers/governor/go-client"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
)

var ClusterID = uuid.New()

type GovernorExporter struct {
}

// SendReportToGovernor is used to send report to governor url http end point.
func (g GovernorExporter) SendReportToGovernor(report *api.AssessmentReport, orgID string) error {
	// Check for clusterID, if not exist, create and assign it to ClusterID.
	getClusterID()

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
	kubernetesCluster := getAPIRequest(*report)
	kubernetesCluster.Name = clusterName

	// Create api client to governor api.
	apiClient := openapi.NewAPIClient(openapi.NewConfiguration())
	apiSaveClusterRequest := apiClient.WorkloadsApi.SaveCluster(context.Background(), orgID, ClusterID.String())

	// Call api cluster to send telemetry data and get response.
	response, err := apiSaveClusterRequest.Cluster(openapi.KubernetesClusterAsCluster(kubernetesCluster)).Execute()
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return errors.New(response.Status)
	}

	return nil
}

// getAPIRequest is used to map assessment report to client model.
func getAPIRequest(doc api.AssessmentReport) *openapi.KubernetesCluster {
	kubernetesCluster := openapi.NewKubernetesClusterWithDefaults()
	for _, nsa := range doc.Spec.NamespaceAssessments {
		for _, workloadAssessment := range nsa.WorkloadAssessments {
			kubernetesCluster.Kind = "KUBERNETES"
			kubernetesWorkloads := openapi.NewKubernetesWorkloadWithDefaults()
			kubernetesWorkloads.Name = workloadAssessment.Workload.Name
			kubernetesWorkloads.Kind = workloadAssessment.Workload.Kind
			kubernetesWorkloads.Namespace = nsa.Namespace.Name
			kubernetesWorkloads.Replicas = *workloadAssessment.Workload.Replicas.Spec.Replicas
			for _, pod := range workloadAssessment.Workload.Pods {
				containerData := openapi.NewContainerWithDefaults()
				for _, container := range pod.Containers {
					containerData.Name = container.Name
					containerData.ImageID = container.ImageID
					containerData.Image = container.Image
					kubernetesWorkloads.Containers = append(kubernetesWorkloads.Containers, *containerData)
				}
			}
			kubernetesCluster.Workloads = append(kubernetesCluster.Workloads, *kubernetesWorkloads)
		}
	}
	return kubernetesCluster
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

func getClusterID() {
	if ClusterID.String() == "" {
		ClusterID = uuid.New()
	}
}
