for port in {8000..9000}; do
  curl -X POST http://localhost:3000/api/profile/upload_picture \
  -H "Content-Type: application/json" \
  -d "{\"picture_url\": \"http://localhost:$port\"}" \
  -w "Port $port: %{http_code}\n" -o /dev/null -s
done
