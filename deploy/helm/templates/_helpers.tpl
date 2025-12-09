{{- define "runtime-security-monitor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "runtime-security-monitor.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "runtime-security-monitor.serviceAccountName" -}}
{{- if .Values.serviceAccountName }}
{{- .Values.serviceAccountName }}
{{- else }}
{{- include "runtime-security-monitor.fullname" . }}
{{- end -}}
{{- end -}}
