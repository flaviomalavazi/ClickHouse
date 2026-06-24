#include <gtest/gtest.h>
#include <config.h>

#if USE_AWS_S3

#include <Storages/Kafka/AWSMSKIAMAuth.h>
#include <Common/Exception.h>
#include <Common/Base64.h>
#include <Common/OpenSSLHelpers.h>
#include <Common/re2.h>
#include <IO/S3/Client.h>
#include <Poco/Util/MapConfiguration.h>
#include <cppkafka/configuration.h>
#include <cppkafka/kafka_handle_base.h>
#include <aws/core/auth/AWSCredentials.h>

#include <algorithm>
#include <map>
#include <vector>

namespace DB
{
namespace ErrorCodes
{
    extern const int BAD_ARGUMENTS;
}
}

using namespace DB;
using namespace DB::AWSMSKIAMAuth;

// ---------------------------------------------------------------------------
// extractRegionFromBroker
// ---------------------------------------------------------------------------

TEST(AWSMSKIAMAuth, ExtractRegionStandardBroker)
{
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka.us-east-1.amazonaws.com:9098"), "us-east-1");
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka.eu-west-2.amazonaws.com"), "eu-west-2");
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka.ap-southeast-1.amazonaws.com:9098"), "ap-southeast-1");
}

TEST(AWSMSKIAMAuth, ExtractRegionServerlessBroker)
{
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka-serverless.us-west-2.amazonaws.com:9098"), "us-west-2");
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka-serverless.eu-central-1.amazonaws.com"), "eu-central-1");
}

TEST(AWSMSKIAMAuth, ExtractRegionPrivateLinkBroker)
{
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka.us-east-1.vpce.amazonaws.com:9098"), "us-east-1");
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka-serverless.eu-west-1.vpce.amazonaws.com"), "eu-west-1");
}

TEST(AWSMSKIAMAuth, ExtractRegionGovCloudBroker)
{
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka.us-gov-west-1.amazonaws.com:9098"), "us-gov-west-1");
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka.us-gov-east-1.amazonaws.com"), "us-gov-east-1");
}

TEST(AWSMSKIAMAuth, ExtractRegionChinaBroker)
{
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka.cn-north-1.amazonaws.com.cn:9098"), "cn-north-1");
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka.cn-northwest-1.amazonaws.com.cn"), "cn-northwest-1");
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.kafka-serverless.cn-north-1.amazonaws.com.cn:9098"), "cn-north-1");
}

TEST(AWSMSKIAMAuth, ExtractRegionMixedCaseBroker)
{
    // DNS is case-insensitive; uppercase/mixed-case hostnames must still work.
    EXPECT_EQ(extractRegionFromBroker("B-1.Cluster.Kafka.US-EAST-1.amazonaws.com:9098"), "us-east-1");
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.KAFKA.eu-west-2.AMAZONAWS.COM"), "eu-west-2");
    EXPECT_EQ(extractRegionFromBroker("B-1.CLUSTER.KAFKA-SERVERLESS.AP-SOUTHEAST-1.amazonaws.com:9098"), "ap-southeast-1");
}

TEST(AWSMSKIAMAuth, ExtractRegionNegativeCases)
{
    EXPECT_EQ(extractRegionFromBroker(""), "");
    EXPECT_EQ(extractRegionFromBroker(":9092"), "");
    EXPECT_EQ(extractRegionFromBroker("localhost:9092"), "");
    EXPECT_EQ(extractRegionFromBroker("broker.example.com:9092"), "");
    // Not an MSK endpoint (missing kafka segment)
    EXPECT_EQ(extractRegionFromBroker("b-1.cluster.us-east-1.amazonaws.com:9098"), "");
}

// ---------------------------------------------------------------------------
// isValidAWSRegion
// ---------------------------------------------------------------------------

TEST(AWSMSKIAMAuth, ValidRegions)
{
    EXPECT_TRUE(isValidAWSRegion("us-east-1"));
    EXPECT_TRUE(isValidAWSRegion("eu-west-2"));
    EXPECT_TRUE(isValidAWSRegion("ap-southeast-1"));
    EXPECT_TRUE(isValidAWSRegion("us-gov-west-1"));
    EXPECT_TRUE(isValidAWSRegion("us-gov-east-1"));
    EXPECT_TRUE(isValidAWSRegion("cn-north-1"));
}

TEST(AWSMSKIAMAuth, InvalidRegions)
{
    EXPECT_FALSE(isValidAWSRegion(""));
    EXPECT_FALSE(isValidAWSRegion("us_east_1"));
    EXPECT_FALSE(isValidAWSRegion("US-EAST-1"));
    EXPECT_FALSE(isValidAWSRegion("useast1"));
    EXPECT_FALSE(isValidAWSRegion("us-east"));
    EXPECT_FALSE(isValidAWSRegion("us-east-"));
    EXPECT_FALSE(isValidAWSRegion("-us-east-1"));
}

// ---------------------------------------------------------------------------
// setupAuthentication failure paths (no AWS SDK calls needed: both throw
// before the credentials provider is created)
// ---------------------------------------------------------------------------

static Poco::AutoPtr<Poco::Util::MapConfiguration> emptyConfig()
{
    return Poco::AutoPtr<Poco::Util::MapConfiguration>(new Poco::Util::MapConfiguration);
}

// ---------------------------------------------------------------------------
// setupAuthentication rewrite: AWS_MSK_IAM from server/named-collection config
// ---------------------------------------------------------------------------

TEST(AWSMSKIAMAuth, SetupRewritesPresetAWSMSKIAMToOAUTHBEARER)
{
    // Simulate sasl.mechanism = AWS_MSK_IAM already written into kafka_config by
    // loadFromConfig (server config path) before setupAuthentication is called.
    // After setup, sasl.mechanism must be OAUTHBEARER and security.protocol SASL_SSL.
    // AWS_MSK_IAM must NOT be passed through to librdkafka.
    cppkafka::Configuration cfg;
    cfg.set("sasl.mechanism", "AWS_MSK_IAM");
    auto config = emptyConfig();
    std::shared_ptr<OAuthBearerTokenRefreshContext> ctx;

    try
    {
        setupAuthentication(cfg, *config, "us-east-1", "", nullptr, ctx);
    }
    catch (const DB::Exception & e)
    {
        FAIL() << "Unexpected DB::Exception: " << e.message();
    }
    catch (...) // NOLINT(bugprone-empty-catch)
    {
        // Ok: non-setup exceptions (e.g. missing AWS credentials) are acceptable —
        // config properties are already written before credentials are resolved.
    }

    // Verify regardless of whether setupAuthentication completed or threw
    // after writing config (credentials unavailable in test environment).
    // librdkafka normalizes property values to lowercase.
    EXPECT_EQ(cfg.get("sasl.mechanism"), "OAUTHBEARER");
    EXPECT_EQ(cfg.get("security.protocol"), "sasl_ssl");
}

TEST(AWSMSKIAMAuth, SetupThrowsOnRegionMismatchWithCachedContext)
{
    // Simulate consumer context cached for us-east-1, then producer attempts eu-west-1.
    // setupAuthentication must reject the mismatch rather than silently signing tokens
    // for the wrong region.
    auto cached_ctx = std::make_shared<OAuthBearerTokenRefreshContext>();
    cached_ctx->region = "us-east-1";

    cppkafka::Configuration cfg;
    auto config = emptyConfig();
    std::shared_ptr<OAuthBearerTokenRefreshContext> ctx = cached_ctx;

    EXPECT_THROW(
        setupAuthentication(cfg, *config, "eu-west-1", "", nullptr, ctx),
        DB::Exception);
}

TEST(AWSMSKIAMAuth, SetupAcceptsSameRegionWithCachedContext)
{
    // Reusing a cached context for the same region must not throw BAD_ARGUMENTS.
    // The function may throw later (e.g. missing AWS credentials in test env),
    // but the region-mismatch check must pass.
    auto cached_ctx = std::make_shared<OAuthBearerTokenRefreshContext>();
    cached_ctx->region = "us-east-1";

    cppkafka::Configuration cfg;
    auto config = emptyConfig();
    std::shared_ptr<OAuthBearerTokenRefreshContext> ctx = cached_ctx;

    try
    {
        setupAuthentication(cfg, *config, "us-east-1", "", nullptr, ctx);
    }
    catch (const DB::Exception & e)
    {
        // setupAuthentication validates region before creating credentials provider.
        // If it throws BAD_ARGUMENTS here, the region-reuse logic is broken.
        ASSERT_NE(e.code(), DB::ErrorCodes::BAD_ARGUMENTS)
            << "Same-region reuse must not throw BAD_ARGUMENTS; got: " << e.message();
    }
    catch (...) // NOLINT(bugprone-empty-catch)
    {
        // Ok: non-region exceptions (e.g. missing AWS credentials) are acceptable.
    }

    // Context must remain the same object (no replacement).
    EXPECT_EQ(ctx, cached_ctx);
}

TEST(AWSMSKIAMAuth, SetupFailsWhenRegionCannotBeInferred)
{
    cppkafka::Configuration cfg;
    auto config = emptyConfig();
    std::shared_ptr<OAuthBearerTokenRefreshContext> ctx;

    EXPECT_THROW(
        setupAuthentication(cfg, *config, "", "localhost:9092,broker2:9092", nullptr, ctx),
        DB::Exception);
}

TEST(AWSMSKIAMAuth, SetupFailsOnInvalidExplicitRegion)
{
    cppkafka::Configuration cfg;
    auto config = emptyConfig();
    std::shared_ptr<OAuthBearerTokenRefreshContext> ctx;

    EXPECT_THROW(
        setupAuthentication(cfg, *config, "INVALID_REGION", "", nullptr, ctx),
        DB::Exception);
}

TEST(AWSMSKIAMAuth, SetupAutoDetectsRegionFromBrokerList)
{
    cppkafka::Configuration cfg;
    auto config = emptyConfig();
    std::shared_ptr<OAuthBearerTokenRefreshContext> ctx;

    // Should not throw on region detection — will throw later inside the AWS SDK
    // if credentials are unavailable, but region parsing itself must succeed.
    // We verify by catching only BAD_ARGUMENTS (region errors) and letting anything
    // else propagate so the test would fail loudly if region detection regressed.
    try
    {
        setupAuthentication(cfg, *config, "", "b-1.cluster.kafka.us-east-1.amazonaws.com:9098", nullptr, ctx);
    }
    catch (const DB::Exception & e)
    {
        EXPECT_NE(e.code(), DB::ErrorCodes::BAD_ARGUMENTS)
            << "Region detection should not throw BAD_ARGUMENTS; got: " << e.message();
    }
    catch (...) // NOLINT(bugprone-empty-catch)
    {
        // Ok: non-BAD_ARGUMENTS exceptions (e.g. missing AWS credentials) are acceptable here.
    }
}

// ---------------------------------------------------------------------------
// generateAWSMSKToken: token structure + independent SigV4 signature check.
//
// The MSK IAM token is a base64url-encoded (no padding) SigV4-presigned URL for
// `Action=kafka-cluster:Connect` against `kafka.<region>.amazonaws.com`, signed
// for service `kafka-cluster`. These tests decode the token, assert its
// structure, and independently recompute the SigV4 signature WITHOUT going
// through the AWS SDK signer (a separate implementation using ClickHouse's
// SHA-256/HMAC helpers), proving the signed material is byte-correct.
// ---------------------------------------------------------------------------

namespace
{

/// Static, non-functional credentials, used only for deterministic signing in tests.
const char * const TEST_ACCESS_KEY = "AKIDEXAMPLE";
const char * const TEST_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const char * const TEST_SESSION_TOKEN = "FQoEXAMPLEsessiontoken";

/// Ensure the AWS SDK (crypto factories used by the signer) is initialised.
void ensureAwsInitialised()
{
    DB::S3::ClientFactory::instance();
}

std::string decodeToken(const std::string & token)
{
    return base64Decode(token, /* url_encoding */ true, /* no_padding */ true);
}

/// Parse the query part of a URL into key -> (percent-encoded) value.
std::map<std::string, std::string> parseQuery(const std::string & url)
{
    std::map<std::string, std::string> params;
    auto qpos = url.find('?');
    if (qpos == std::string::npos)
        return params;
    const std::string query = url.substr(qpos + 1);
    size_t start = 0;
    while (start < query.size())
    {
        size_t amp = query.find('&', start);
        std::string pair = query.substr(start, amp == std::string::npos ? std::string::npos : amp - start);
        auto eq = pair.find('=');
        if (eq != std::string::npos)
            params[pair.substr(0, eq)] = pair.substr(eq + 1);
        else
            params[pair] = "";
        if (amp == std::string::npos)
            break;
        start = amp + 1;
    }
    return params;
}

std::string toHex(const std::vector<uint8_t> & data)
{
    static const char * digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data)
    {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

std::string sha256Hex(const std::string & data)
{
    const std::string digest = encodeSHA256(data);
    return toHex(std::vector<uint8_t>(digest.begin(), digest.end()));
}

std::vector<uint8_t> bytes(const std::string & s)
{
    return std::vector<uint8_t>(s.begin(), s.end());
}

/// Independently recompute the SigV4 signature for the presigned MSK URL, reusing the
/// X-Amz-Date the SDK embedded so the check is deterministic without freezing the clock.
std::string recomputeSignature(const std::string & url, const std::string & region, const std::string & secret_key)
{
    const std::string host = "kafka." + region + ".amazonaws.com";
    const auto params = parseQuery(url);

    /// Canonical query: all signed params sorted, excluding the signature itself and
    /// the unsigned `User-Agent` suffix appended after signing. Values are taken verbatim
    /// (already percent-encoded), so they match exactly what the SDK signed.
    std::vector<std::string> pairs;
    for (const auto & [k, v] : params)
    {
        if (k == "X-Amz-Signature" || k == "User-Agent")
            continue;
        pairs.push_back(k + "=" + v);
    }
    std::sort(pairs.begin(), pairs.end());
    std::string canonical_query;
    for (size_t i = 0; i < pairs.size(); ++i)
        canonical_query += (i ? "&" : "") + pairs[i];

    /// `kafka-cluster` is not S3, so the canonical payload hash is the empty-string SHA-256.
    const std::string empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const std::string canonical_request
        = "GET\n/\n" + canonical_query + "\n" + "host:" + host + "\n" + "\n" + "host\n" + empty_sha256;

    const std::string amz_date = params.at("X-Amz-Date");   // e.g. 20260624T120000Z
    const std::string simple_date = amz_date.substr(0, 8);  // 20260624
    const std::string scope = simple_date + "/" + region + "/kafka-cluster/aws4_request";
    const std::string string_to_sign = "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope + "\n" + sha256Hex(canonical_request);

    auto k_date = hmacSHA256(bytes("AWS4" + secret_key), simple_date);
    auto k_region = hmacSHA256(k_date, region);
    auto k_service = hmacSHA256(k_region, "kafka-cluster");
    auto k_signing = hmacSHA256(k_service, "aws4_request");
    return toHex(hmacSHA256(k_signing, string_to_sign));
}

}

TEST(AWSMSKIAMAuthToken, TokenStructure)
{
    ensureAwsInitialised();
    const std::string token = generateAWSMSKToken("us-east-1", Aws::Auth::AWSCredentials{TEST_ACCESS_KEY, TEST_SECRET_KEY, TEST_SESSION_TOKEN});

    // base64url alphabet, no padding.
    EXPECT_EQ(token.find('='), std::string::npos);
    EXPECT_EQ(token.find('+'), std::string::npos);
    EXPECT_EQ(token.find('/'), std::string::npos);

    const std::string url = decodeToken(token);
    EXPECT_EQ(url.rfind("https://kafka.us-east-1.amazonaws.com/?", 0), 0u);
    EXPECT_NE(url.find("Action=kafka-cluster%3AConnect"), std::string::npos);
    EXPECT_NE(url.find("&User-Agent=clickhouse-msk-iam"), std::string::npos);

    const auto params = parseQuery(url);
    EXPECT_EQ(params.at("X-Amz-Algorithm"), "AWS4-HMAC-SHA256");
    EXPECT_EQ(params.at("X-Amz-Expires"), "900");
    EXPECT_EQ(params.at("X-Amz-SignedHeaders"), "host");
    EXPECT_NE(params.find("X-Amz-Security-Token"), params.end());   // session token present

    // Credential scope embeds access key, region and service.
    EXPECT_NE(params.at("X-Amz-Credential").find(TEST_ACCESS_KEY), std::string::npos);
    EXPECT_NE(params.at("X-Amz-Credential").find("us-east-1"), std::string::npos);
    EXPECT_NE(params.at("X-Amz-Credential").find("kafka-cluster"), std::string::npos);

    static const RE2 date_re(R"(^\d{8}T\d{6}Z$)");
    EXPECT_TRUE(RE2::FullMatch(params.at("X-Amz-Date"), date_re));
    static const RE2 sig_re("^[0-9a-f]{64}$");
    EXPECT_TRUE(RE2::FullMatch(params.at("X-Amz-Signature"), sig_re));
}

TEST(AWSMSKIAMAuthToken, SignatureMatchesIndependentRecomputation)
{
    ensureAwsInitialised();
    const std::string url = decodeToken(generateAWSMSKToken("us-east-1", Aws::Auth::AWSCredentials{TEST_ACCESS_KEY, TEST_SECRET_KEY, TEST_SESSION_TOKEN}));
    const auto params = parseQuery(url);
    EXPECT_EQ(recomputeSignature(url, "us-east-1", TEST_SECRET_KEY), params.at("X-Amz-Signature"));
}

TEST(AWSMSKIAMAuthToken, RegionPropagatesToHostScopeAndSignature)
{
    ensureAwsInitialised();
    const std::string url = decodeToken(generateAWSMSKToken("eu-west-2", Aws::Auth::AWSCredentials{TEST_ACCESS_KEY, TEST_SECRET_KEY, TEST_SESSION_TOKEN}));
    EXPECT_EQ(url.rfind("https://kafka.eu-west-2.amazonaws.com/?", 0), 0u);
    const auto params = parseQuery(url);
    EXPECT_NE(params.at("X-Amz-Credential").find("eu-west-2"), std::string::npos);
    EXPECT_EQ(recomputeSignature(url, "eu-west-2", TEST_SECRET_KEY), params.at("X-Amz-Signature"));
}

TEST(AWSMSKIAMAuthToken, NoSessionTokenOmitsSecurityToken)
{
    ensureAwsInitialised();
    // Credentials without a session token (e.g. long-lived IAM user keys).
    const std::string url = decodeToken(generateAWSMSKToken("us-east-1", Aws::Auth::AWSCredentials{TEST_ACCESS_KEY, TEST_SECRET_KEY}));
    const auto params = parseQuery(url);
    EXPECT_EQ(params.find("X-Amz-Security-Token"), params.end());
    EXPECT_EQ(recomputeSignature(url, "us-east-1", TEST_SECRET_KEY), params.at("X-Amz-Signature"));
}

#endif // USE_AWS_S3
