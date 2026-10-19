#include "nvme_latency/http_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace nvme_bpf {
namespace {

using ::testing::HasSubstr;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

TEST(UrlDecodeTest, Decodes) {
  EXPECT_EQ(UrlDecode("a%20b+c", /*plus_is_space=*/true), "a b c");
  EXPECT_EQ(UrlDecode("a%20b+c", /*plus_is_space=*/false), "a b+c");
  EXPECT_EQ(UrlDecode("100%", true), "100%");
  EXPECT_EQ(UrlDecode("%zz%4a", true), "%zzJ");
}

TEST(ParseHttpRequestTest, ParsesRequestLineAndQuery) {
  absl::StatusOr<HttpRequest> r = ParseHttpRequest(
      "GET /api/series?window_s=60&name=a%20b+c&flag HTTP/1.1\r\n"
      "Host: localhost\r\n\r\n");
  ASSERT_TRUE(r.ok()) << r.status();
  EXPECT_EQ(r->method, "GET");
  EXPECT_EQ(r->path, "/api/series");
  EXPECT_THAT(r->query, UnorderedElementsAre(Pair("window_s", "60"),
                                             Pair("name", "a b c"),
                                             Pair("flag", "")));
  EXPECT_EQ(r->QueryParam("window_s"), "60");
  EXPECT_EQ(r->QueryParam("missing", "dflt"), "dflt");
}

TEST(ParseHttpRequestTest, RejectsMalformed) {
  EXPECT_FALSE(ParseHttpRequest("GET /\r\n\r\n").ok());
  EXPECT_FALSE(ParseHttpRequest("GET / FTP/1.0\r\n\r\n").ok());
  EXPECT_FALSE(ParseHttpRequest("GET http://x/ HTTP/1.1\r\n\r\n").ok());
  EXPECT_FALSE(ParseHttpRequest("garbage").ok());
}

// Sends `request` to the server on localhost and returns the raw response.
std::string Fetch(int port, const std::string& request) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  EXPECT_GE(fd, 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  EXPECT_EQ(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
  EXPECT_EQ(send(fd, request.data(), request.size(), 0),
            static_cast<ssize_t>(request.size()));
  std::string response;
  char buf[4096];
  ssize_t n;
  while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) response.append(buf, n);
  close(fd);
  return response;
}

class HttpServerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    server_.AddHandler("/hello", [](const HttpRequest& r) {
      HttpResponse response;
      response.body = absl::StrCat("hello ", r.QueryParam("name", "world"));
      response.headers.push_back({"X-Test", "1"});
      return response;
    });
    ASSERT_TRUE(server_.Start("127.0.0.1", 0).ok());
    ASSERT_GT(server_.port(), 0);
  }

  HttpServer server_;
};

TEST_F(HttpServerTest, ServesHandler) {
  const std::string response =
      Fetch(server_.port(), "GET /hello?name=nvme HTTP/1.1\r\nHost: x\r\n\r\n");
  EXPECT_TRUE(absl::StartsWith(response, "HTTP/1.1 200 OK\r\n")) << response;
  EXPECT_THAT(response, HasSubstr("Content-Length: 10\r\n"));
  EXPECT_THAT(response, HasSubstr("X-Test: 1\r\n"));
  EXPECT_TRUE(absl::EndsWith(response, "\r\n\r\nhello nvme")) << response;
}

TEST_F(HttpServerTest, HeadOmitsBody) {
  const std::string response =
      Fetch(server_.port(), "HEAD /hello HTTP/1.1\r\n\r\n");
  EXPECT_TRUE(absl::StartsWith(response, "HTTP/1.1 200 OK\r\n")) << response;
  EXPECT_THAT(response, HasSubstr("Content-Length: 11\r\n"));
  EXPECT_TRUE(absl::EndsWith(response, "\r\n\r\n")) << response;
}

TEST_F(HttpServerTest, NotFound) {
  EXPECT_TRUE(absl::StartsWith(
      Fetch(server_.port(), "GET /nope HTTP/1.1\r\n\r\n"), "HTTP/1.1 404"));
}

TEST_F(HttpServerTest, MethodNotAllowed) {
  const std::string response =
      Fetch(server_.port(), "POST /hello HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
  EXPECT_TRUE(absl::StartsWith(response, "HTTP/1.1 405")) << response;
  EXPECT_THAT(response, HasSubstr("Allow: GET, HEAD\r\n"));
}

TEST_F(HttpServerTest, BadRequest) {
  EXPECT_TRUE(absl::StartsWith(Fetch(server_.port(), "nonsense\r\n\r\n"),
                               "HTTP/1.1 400"));
}

TEST_F(HttpServerTest, ManySequentialRequests) {
  for (int i = 0; i < 50; ++i) {
    ASSERT_TRUE(absl::StartsWith(
        Fetch(server_.port(), "GET /hello HTTP/1.1\r\n\r\n"), "HTTP/1.1 200"))
        << i;
  }
}

TEST(HttpServerStopTest, StopIsIdempotent) {
  HttpServer server;
  ASSERT_TRUE(server.Start("127.0.0.1", 0).ok());
  server.Stop();
  server.Stop();
}

TEST(HttpServerStopTest, BadAddress) {
  HttpServer server;
  EXPECT_FALSE(server.Start("not an address!", 0).ok());
}

}  // namespace
}  // namespace nvme_bpf
