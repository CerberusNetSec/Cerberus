{{- define "cerberus.name" -}}cerberus{{- end -}}

{{- define "cerberus.fullname" -}}
{{- if contains "cerberus" .Release.Name -}}{{ .Release.Name | trunc 50 | trimSuffix "-" }}{{- else -}}{{ printf "%s-cerberus" .Release.Name | trunc 50 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "cerberus.labels" -}}
app.kubernetes.io/name: cerberus
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "cerberus.selector" -}}
app.kubernetes.io/name: cerberus
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "cerberus.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "cerberus.authSecret" -}}{{ .Values.auth.existingSecret | default (printf "%s-auth" (include "cerberus.fullname" .)) }}{{- end -}}
{{- define "cerberus.storageSecret" -}}{{ .Values.storage.existingSecret | default (printf "%s-storage" (include "cerberus.fullname" .)) }}{{- end -}}
{{- define "cerberus.kafkaSecret" -}}{{ .Values.kafka.sasl.existingSecret | default (printf "%s-kafka" (include "cerberus.fullname" .)) }}{{- end -}}
{{- define "cerberus.oidcSecret" -}}{{ .Values.oidc.existingSecret | default (printf "%s-oidc" (include "cerberus.fullname" .)) }}{{- end -}}
{{- define "cerberus.urlsFrom" -}}{{ if and .Values.storage.postgresUrlFrom.secret .Values.storage.clickhouseUrlFrom.secret }}true{{ end }}{{- end -}}
{{- define "cerberus.clustered" -}}{{ if or (eq .Values.mode "scaleOut") (eq .Values.storage.type "clustered") }}true{{ end }}{{- end -}}
{{- define "cerberus.sasl" -}}{{ if hasPrefix "SASL_" .Values.kafka.security }}true{{ end }}{{- end -}}

{{/* Environment shared by every Cerberus container: secrets as _FILE paths. */}}
{{- define "cerberus.hasPassword" -}}{{ if or .Values.auth.password .Values.auth.existingSecret }}true{{ end }}{{- end -}}

{{- define "cerberus.env" -}}
{{- if include "cerberus.hasPassword" . }}
- {name: CERBERUS_PASSWORD_FILE, value: /run/secrets/cerberus/auth/password}
{{- end }}
{{- if .Values.publicUrl }}
- {name: CERBERUS_PUBLIC_URL, value: {{ .Values.publicUrl | quote }}}
{{- end }}
{{- if include "cerberus.urlsFrom" . }}
- name: CERBERUS_POSTGRES_URL
  valueFrom: {secretKeyRef: {name: {{ .Values.storage.postgresUrlFrom.secret }}, key: {{ .Values.storage.postgresUrlFrom.key }}}}
- name: CERBERUS_CLICKHOUSE_URL
  valueFrom: {secretKeyRef: {name: {{ .Values.storage.clickhouseUrlFrom.secret }}, key: {{ .Values.storage.clickhouseUrlFrom.key }}}}
{{- else if include "cerberus.clustered" . }}
- {name: CERBERUS_POSTGRES_URL_FILE, value: /run/secrets/cerberus/storage/postgres-url}
- {name: CERBERUS_CLICKHOUSE_URL_FILE, value: /run/secrets/cerberus/storage/clickhouse-url}
{{- end }}
{{- if eq .Values.mode "scaleOut" }}
- {name: CERBERUS_KAFKA_BOOTSTRAP, value: {{ .Values.kafka.bootstrap | quote }}}
- {name: CERBERUS_KAFKA_TOPIC, value: {{ .Values.kafka.topic | quote }}}
- {name: CERBERUS_KAFKA_PARTITIONS, value: {{ .Values.kafka.partitions | quote }}}
- {name: CERBERUS_KAFKA_REPLICATION, value: {{ .Values.kafka.replication | quote }}}
- {name: CERBERUS_KAFKA_SECURITY, value: {{ .Values.kafka.security | quote }}}
{{- if .Values.kafka.caSecret }}
- {name: CERBERUS_KAFKA_CA, value: /run/secrets/cerberus/kafka-ca/ca.crt}
{{- end }}
{{- if include "cerberus.sasl" . }}
- {name: CERBERUS_KAFKA_SASL_MECHANISM, value: {{ .Values.kafka.sasl.mechanism | quote }}}
- {name: CERBERUS_KAFKA_USERNAME, value: {{ required "kafka.sasl.username is required for SASL" .Values.kafka.sasl.username | quote }}}
- {name: CERBERUS_KAFKA_PASSWORD_FILE, value: {{ printf "/run/secrets/cerberus/kafka/%s" .Values.kafka.sasl.passwordKey | quote }}}
{{- end }}
- {name: CERBERUS_DETECTION_WORKERS, value: {{ if .Values.detectors.enabled }}{{ keys .Values.detectors.families | sortAlpha | join "," | quote }}{{ else }}""{{ end }}}
{{- end }}
{{- if .Values.oidc.issuer }}
- {name: CERBERUS_OIDC_ISSUER, value: {{ .Values.oidc.issuer | quote }}}
- {name: CERBERUS_OIDC_CLIENT_ID, value: {{ required "oidc.clientId is required" .Values.oidc.clientId | quote }}}
- {name: CERBERUS_OIDC_CLIENT_SECRET_FILE, value: /run/secrets/cerberus/oidc/client-secret}
- {name: CERBERUS_OIDC_ROLE_CLAIM, value: {{ .Values.oidc.roleClaim | quote }}}
- {name: CERBERUS_OIDC_ADMIN_GROUPS, value: {{ .Values.oidc.adminGroups | quote }}}
- {name: CERBERUS_OIDC_ANALYST_GROUPS, value: {{ .Values.oidc.analystGroups | quote }}}
- {name: CERBERUS_OIDC_VIEWER_GROUPS, value: {{ .Values.oidc.viewerGroups | quote }}}
- {name: CERBERUS_OIDC_DEFAULT_ROLE, value: {{ .Values.oidc.defaultRole | quote }}}
{{- if .Values.oidc.label }}
- {name: CERBERUS_OIDC_LABEL, value: {{ .Values.oidc.label | quote }}}
{{- end }}
{{- end }}
{{- if .Values.metrics.token }}
- {name: CERBERUS_METRICS_TOKEN, valueFrom: {secretKeyRef: {name: {{ printf "%s-metrics" (include "cerberus.fullname" .) }}, key: token}}}
{{- end }}
{{- range $k, $v := .Values.config }}
- {name: {{ $k }}, value: {{ $v | quote }}}
{{- end }}
{{- end -}}

{{- define "cerberus.mounts" -}}
{{- if include "cerberus.hasPassword" . }}
- {name: auth, mountPath: /run/secrets/cerberus/auth, readOnly: true}
{{- end }}
{{- if and (include "cerberus.clustered" .) (not (include "cerberus.urlsFrom" .)) }}
- {name: storage, mountPath: /run/secrets/cerberus/storage, readOnly: true}
{{- end }}
{{- if and (eq .Values.mode "scaleOut") (include "cerberus.sasl" .) }}
- {name: kafka, mountPath: /run/secrets/cerberus/kafka, readOnly: true}
{{- end }}
{{- if and (eq .Values.mode "scaleOut") .Values.kafka.caSecret }}
- {name: kafka-ca, mountPath: /run/secrets/cerberus/kafka-ca, readOnly: true}
{{- end }}
{{- if .Values.oidc.issuer }}
- {name: oidc, mountPath: /run/secrets/cerberus/oidc, readOnly: true}
{{- end }}
{{- end -}}

{{- define "cerberus.volumes" -}}
{{- if include "cerberus.hasPassword" . }}
- name: auth
  secret: {secretName: {{ include "cerberus.authSecret" . }}, defaultMode: 0440}
{{- end }}
{{- if and (include "cerberus.clustered" .) (not (include "cerberus.urlsFrom" .)) }}
- name: storage
  secret: {secretName: {{ include "cerberus.storageSecret" . }}, defaultMode: 0440}
{{- end }}
{{- if and (eq .Values.mode "scaleOut") (include "cerberus.sasl" .) }}
- name: kafka
  secret: {secretName: {{ include "cerberus.kafkaSecret" . }}, defaultMode: 0440}
{{- end }}
{{- if and (eq .Values.mode "scaleOut") .Values.kafka.caSecret }}
- name: kafka-ca
  secret: {secretName: {{ .Values.kafka.caSecret }}, defaultMode: 0440}
{{- end }}
{{- if .Values.oidc.issuer }}
- name: oidc
  secret: {secretName: {{ include "cerberus.oidcSecret" . }}, defaultMode: 0440}
{{- end }}
{{- end -}}

{{- define "cerberus.podAnnotations" -}}
{{- if .Values.metrics.podAnnotations }}
prometheus.io/scrape: "true"
prometheus.io/port: "8080"
prometheus.io/path: /metrics
{{- end }}
{{- end -}}

{{- define "cerberus.syslogPorts" -}}
{{- if .Values.syslog.tcp }}
- {name: syslog-tcp, containerPort: 5514, protocol: TCP}
{{- end }}
{{- if .Values.syslog.udp }}
- {name: syslog-udp, containerPort: 5514, protocol: UDP}
{{- end }}
{{- if .Values.syslog.tls.enabled }}
- {name: syslog-tls, containerPort: 6514, protocol: TCP}
{{- end }}
{{- end -}}

{{- define "cerberus.syslogEnv" -}}
- {name: CERBERUS_SYSLOG_TCP_PORT, value: {{ ternary "5514" "0" .Values.syslog.tcp | quote }}}
- {name: CERBERUS_SYSLOG_UDP_PORT, value: {{ ternary "5514" "0" .Values.syslog.udp | quote }}}
{{- if .Values.syslog.tls.enabled }}
- {name: CERBERUS_SYSLOG_TLS_PORT, value: "6514"}
- {name: CERBERUS_SYSLOG_TLS_CERT, value: /run/secrets/cerberus/tls/tls.crt}
- {name: CERBERUS_SYSLOG_TLS_KEY, value: /run/secrets/cerberus/tls/tls.key}
{{- if .Values.syslog.tls.requireClientCertificates }}
- {name: CERBERUS_SYSLOG_TLS_CLIENT_CA, value: /run/secrets/cerberus/tls/ca.crt}
{{- end }}
{{- end }}
{{- end -}}
