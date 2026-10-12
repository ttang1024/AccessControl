# Build: docker build -t access-control .
# Run:   docker run -p 8080:8080 -v acs-data:/data \
#          -e Storage__AuditHmacKey=... -e Storage__CardNumberKey=... -e AllowedHosts=acs.example.com \
#          -e Auth__ApiKeys__0__Name=... access-control
# One container per data volume: a second instance on the same volume fails at startup (data-directory lock).
# Deploy with stop-then-start (Kubernetes: strategy Recreate), not a rolling update.
# Base images are pinned by tag; pin by digest (image@sha256:...) in your registry policy for reproducible builds.
# Terminate TLS in front of the container and set ASPNETCORE_FORWARDEDHEADERS_ENABLED=true (see README).

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY global.json Directory.Build.props ./
COPY src/ src/
# Tests run in CI (.github/workflows/ci.yml) before the image is built; the image only builds what it ships.
RUN dotnet restore src/AccessControl.Api
RUN dotnet publish src/AccessControl.Api -c Release --no-restore -o /app

# The aspnet image includes tzdata, which schedules need to resolve their IANA time zones.
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
RUN mkdir /data && chown app:app /data
USER app
ENV ASPNETCORE_URLS=http://+:8080 \
    Storage__DataDirectory=/data
VOLUME /data
EXPOSE 8080
# No HEALTHCHECK: the image has no HTTP client. Point the orchestrator at /health/live (liveness) and /health (readiness).
ENTRYPOINT ["dotnet", "AccessControl.Api.dll"]
