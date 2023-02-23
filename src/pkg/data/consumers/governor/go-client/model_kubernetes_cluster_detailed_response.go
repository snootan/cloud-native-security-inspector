/*
Catalog Governor Service REST API

This is the service to track assets deployed in customer clusters

API version: 0.1.0
Contact: content-building-ecosystem@vmware.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"encoding/json"
	"time"
)

// KubernetesClusterDetailedResponse A Kubernetes cluster with its metadata, workloads and audit information included
type KubernetesClusterDetailedResponse struct {
	// id of the cluster where the workloads are deployed
	Id string `json:"id"`
	// name of the cluster where the workloads are deployed
	Name string `json:"name"`
	// Creation date
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// Last updated date
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// User who created the cluster
	CreatedBy *string `json:"created_by,omitempty"`
	// User who last updated the cluster
	UpdatedBy *string `json:"updated_by,omitempty"`
	Telemetry *KubernetesTelemetryResponse `json:"telemetry,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _KubernetesClusterDetailedResponse KubernetesClusterDetailedResponse

// NewKubernetesClusterDetailedResponse instantiates a new KubernetesClusterDetailedResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewKubernetesClusterDetailedResponse(id string, name string) *KubernetesClusterDetailedResponse {
	this := KubernetesClusterDetailedResponse{}
	this.Id = id
	this.Name = name
	return &this
}

// NewKubernetesClusterDetailedResponseWithDefaults instantiates a new KubernetesClusterDetailedResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewKubernetesClusterDetailedResponseWithDefaults() *KubernetesClusterDetailedResponse {
	this := KubernetesClusterDetailedResponse{}
	return &this
}

// GetId returns the Id field value
func (o *KubernetesClusterDetailedResponse) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *KubernetesClusterDetailedResponse) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *KubernetesClusterDetailedResponse) SetId(v string) {
	o.Id = v
}

// GetName returns the Name field value
func (o *KubernetesClusterDetailedResponse) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *KubernetesClusterDetailedResponse) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *KubernetesClusterDetailedResponse) SetName(v string) {
	o.Name = v
}

// GetCreatedAt returns the CreatedAt field value if set, zero value otherwise.
func (o *KubernetesClusterDetailedResponse) GetCreatedAt() time.Time {
	if o == nil || o.CreatedAt == nil {
		var ret time.Time
		return ret
	}
	return *o.CreatedAt
}

// GetCreatedAtOk returns a tuple with the CreatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KubernetesClusterDetailedResponse) GetCreatedAtOk() (*time.Time, bool) {
	if o == nil || o.CreatedAt == nil {
		return nil, false
	}
	return o.CreatedAt, true
}

// HasCreatedAt returns a boolean if a field has been set.
func (o *KubernetesClusterDetailedResponse) HasCreatedAt() bool {
	if o != nil && o.CreatedAt != nil {
		return true
	}

	return false
}

// SetCreatedAt gets a reference to the given time.Time and assigns it to the CreatedAt field.
func (o *KubernetesClusterDetailedResponse) SetCreatedAt(v time.Time) {
	o.CreatedAt = &v
}

// GetUpdatedAt returns the UpdatedAt field value if set, zero value otherwise.
func (o *KubernetesClusterDetailedResponse) GetUpdatedAt() time.Time {
	if o == nil || o.UpdatedAt == nil {
		var ret time.Time
		return ret
	}
	return *o.UpdatedAt
}

// GetUpdatedAtOk returns a tuple with the UpdatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KubernetesClusterDetailedResponse) GetUpdatedAtOk() (*time.Time, bool) {
	if o == nil || o.UpdatedAt == nil {
		return nil, false
	}
	return o.UpdatedAt, true
}

// HasUpdatedAt returns a boolean if a field has been set.
func (o *KubernetesClusterDetailedResponse) HasUpdatedAt() bool {
	if o != nil && o.UpdatedAt != nil {
		return true
	}

	return false
}

// SetUpdatedAt gets a reference to the given time.Time and assigns it to the UpdatedAt field.
func (o *KubernetesClusterDetailedResponse) SetUpdatedAt(v time.Time) {
	o.UpdatedAt = &v
}

// GetCreatedBy returns the CreatedBy field value if set, zero value otherwise.
func (o *KubernetesClusterDetailedResponse) GetCreatedBy() string {
	if o == nil || o.CreatedBy == nil {
		var ret string
		return ret
	}
	return *o.CreatedBy
}

// GetCreatedByOk returns a tuple with the CreatedBy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KubernetesClusterDetailedResponse) GetCreatedByOk() (*string, bool) {
	if o == nil || o.CreatedBy == nil {
		return nil, false
	}
	return o.CreatedBy, true
}

// HasCreatedBy returns a boolean if a field has been set.
func (o *KubernetesClusterDetailedResponse) HasCreatedBy() bool {
	if o != nil && o.CreatedBy != nil {
		return true
	}

	return false
}

// SetCreatedBy gets a reference to the given string and assigns it to the CreatedBy field.
func (o *KubernetesClusterDetailedResponse) SetCreatedBy(v string) {
	o.CreatedBy = &v
}

// GetUpdatedBy returns the UpdatedBy field value if set, zero value otherwise.
func (o *KubernetesClusterDetailedResponse) GetUpdatedBy() string {
	if o == nil || o.UpdatedBy == nil {
		var ret string
		return ret
	}
	return *o.UpdatedBy
}

// GetUpdatedByOk returns a tuple with the UpdatedBy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KubernetesClusterDetailedResponse) GetUpdatedByOk() (*string, bool) {
	if o == nil || o.UpdatedBy == nil {
		return nil, false
	}
	return o.UpdatedBy, true
}

// HasUpdatedBy returns a boolean if a field has been set.
func (o *KubernetesClusterDetailedResponse) HasUpdatedBy() bool {
	if o != nil && o.UpdatedBy != nil {
		return true
	}

	return false
}

// SetUpdatedBy gets a reference to the given string and assigns it to the UpdatedBy field.
func (o *KubernetesClusterDetailedResponse) SetUpdatedBy(v string) {
	o.UpdatedBy = &v
}

// GetTelemetry returns the Telemetry field value if set, zero value otherwise.
func (o *KubernetesClusterDetailedResponse) GetTelemetry() KubernetesTelemetryResponse {
	if o == nil || o.Telemetry == nil {
		var ret KubernetesTelemetryResponse
		return ret
	}
	return *o.Telemetry
}

// GetTelemetryOk returns a tuple with the Telemetry field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KubernetesClusterDetailedResponse) GetTelemetryOk() (*KubernetesTelemetryResponse, bool) {
	if o == nil || o.Telemetry == nil {
		return nil, false
	}
	return o.Telemetry, true
}

// HasTelemetry returns a boolean if a field has been set.
func (o *KubernetesClusterDetailedResponse) HasTelemetry() bool {
	if o != nil && o.Telemetry != nil {
		return true
	}

	return false
}

// SetTelemetry gets a reference to the given KubernetesTelemetryResponse and assigns it to the Telemetry field.
func (o *KubernetesClusterDetailedResponse) SetTelemetry(v KubernetesTelemetryResponse) {
	o.Telemetry = &v
}

func (o KubernetesClusterDetailedResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["id"] = o.Id
	}
	if true {
		toSerialize["name"] = o.Name
	}
	if o.CreatedAt != nil {
		toSerialize["created_at"] = o.CreatedAt
	}
	if o.UpdatedAt != nil {
		toSerialize["updated_at"] = o.UpdatedAt
	}
	if o.CreatedBy != nil {
		toSerialize["created_by"] = o.CreatedBy
	}
	if o.UpdatedBy != nil {
		toSerialize["updated_by"] = o.UpdatedBy
	}
	if o.Telemetry != nil {
		toSerialize["telemetry"] = o.Telemetry
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *KubernetesClusterDetailedResponse) UnmarshalJSON(bytes []byte) (err error) {
	varKubernetesClusterDetailedResponse := _KubernetesClusterDetailedResponse{}

	if err = json.Unmarshal(bytes, &varKubernetesClusterDetailedResponse); err == nil {
		*o = KubernetesClusterDetailedResponse(varKubernetesClusterDetailedResponse)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "id")
		delete(additionalProperties, "name")
		delete(additionalProperties, "created_at")
		delete(additionalProperties, "updated_at")
		delete(additionalProperties, "created_by")
		delete(additionalProperties, "updated_by")
		delete(additionalProperties, "telemetry")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableKubernetesClusterDetailedResponse struct {
	value *KubernetesClusterDetailedResponse
	isSet bool
}

func (v NullableKubernetesClusterDetailedResponse) Get() *KubernetesClusterDetailedResponse {
	return v.value
}

func (v *NullableKubernetesClusterDetailedResponse) Set(val *KubernetesClusterDetailedResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableKubernetesClusterDetailedResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableKubernetesClusterDetailedResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKubernetesClusterDetailedResponse(val *KubernetesClusterDetailedResponse) *NullableKubernetesClusterDetailedResponse {
	return &NullableKubernetesClusterDetailedResponse{value: val, isSet: true}
}

func (v NullableKubernetesClusterDetailedResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKubernetesClusterDetailedResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


