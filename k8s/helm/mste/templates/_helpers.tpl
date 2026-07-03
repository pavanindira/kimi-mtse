{{/*
_helpers.tpl — Shared template functions for the MSTE Helm chart.
*/}}

{{/* Chart name */}}
{{- define "mste.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Full name: release-chart, capped at 63 chars */}}
{{- define "mste.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Chart label: name-version */}}
{{- define "mste.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels applied to all resources */}}
{{- define "mste.labels" -}}
helm.sh/chart: {{ include "mste.chart" . }}
{{ include "mste.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels — used in Deployment/Service matchLabels */}}
{{- define "mste.selectorLabels" -}}
app.kubernetes.io/name:     {{ include "mste.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
