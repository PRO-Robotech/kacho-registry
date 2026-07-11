{{/*
Helper templates for the kacho-registry sub-chart.
*/}}

{{/*
registry.fullname — the workload/base name. Driven by .Values.name (== Chart name
`registry`) so the Deployment, public Service and cert-SANs all agree.
*/}}
{{- define "registry.fullname" -}}
{{ .Values.name }}
{{- end -}}

{{/*
registry.image — kacho-registry container image reference (api-server + migrator
share one image). Prefers an immutable digest pin when .Values.image.digest is set
(repository@sha256:...); otherwise repository:tag.
*/}}
{{- define "registry.image" -}}
{{- $img := .Values.image -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ $img.tag }}
{{- end -}}
{{- end -}}

{{/*
registry.zotImage — zot OCI backend image reference (same digest-pin logic).
*/}}
{{- define "registry.zotImage" -}}
{{- $z := .Values.zot.image -}}
{{- if $z.digest -}}
{{ $z.repository }}@{{ $z.digest }}
{{- else -}}
{{ $z.repository }}:{{ $z.tag }}
{{- end -}}
{{- end -}}

{{/*
registry.zotAddr — the ZOT_ADDR the registry dials. Explicit .Values.zot.addr wins;
otherwise derived from the zot Service name + port (http://<serviceName>:<port>).
*/}}
{{- define "registry.zotAddr" -}}
{{- if .Values.zot.addr -}}
{{ .Values.zot.addr }}
{{- else -}}
http://{{ .Values.zot.serviceName }}:{{ .Values.zot.port }}
{{- end -}}
{{- end -}}
