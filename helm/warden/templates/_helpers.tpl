{{- define "warden.fullname" -}}
{{- printf "%s-%s" .Release.Name "warden" -}}
{{- end -}}

{{- define "warden.name" -}}
warden
{{- end -}}
