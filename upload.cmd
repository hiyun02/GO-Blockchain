@echo off
setlocal

set URL=http://localhost:6003/mine

echo Uploading VID-00016
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00016\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"storage_addr\":\"s3://bucket/d.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00017
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00017\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"storage_addr\":\"s3://bucket/a.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00018
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00018\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"storage_addr\":\"s3://bucket/b.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00019
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00019\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"storage_addr\":\"s3://bucket/c.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00020
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00020\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"storage_addr\":\"s3://bucket/d.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00021
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00021\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"storage_addr\":\"s3://bucket/a.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00022
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00022\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"storage_addr\":\"s3://bucket/b.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00023
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00023\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"storage_addr\":\"s3://bucket/c.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00024
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00024\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"storage_addr\":\"s3://bucket/d.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo Uploading VID-00025
curl -X POST %URL% -H "Content-Type: application/json" -d "{\"content_id\":\"VID-00025\",\"info\":{\"title\":\"Demo\",\"region\":\"KR\"},\"fingerprint\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"storage_addr\":\"s3://bucket/a.mp4\",\"drm\":null,\"timestamp\":\"2025-11-17T01:15:44Z\"}"

echo === 업로드 완료 ===
pause
