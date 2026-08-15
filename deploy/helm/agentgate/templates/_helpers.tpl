{{- define "agentgate.name" -}}
agentgate
{{- end -}}

{{- define "agentgate.labels" -}}
app.kubernetes.io/name: {{ include "agentgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
