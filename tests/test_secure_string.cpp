#include <gtest/gtest.h>
#include "secure_string.h"
#include <cstring>

TEST(SecureString, DefaultIsEmpty)
{
    SecureString s;
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
    // c_str on an empty SecureString must still return a valid NUL-terminated buffer.
    EXPECT_STREQ(s.c_str(), "");
}

TEST(SecureString, AssignAndReadBack)
{
    SecureString s;
    const char *pin = "123456";
    s.assign(pin, std::strlen(pin));

    EXPECT_FALSE(s.empty());
    EXPECT_EQ(s.size(), 6u);
    EXPECT_STREQ(s.c_str(), "123456");
}

TEST(SecureString, AssignOverwritesPrevious)
{
    SecureString s;
    s.assign("old", 3);
    s.assign("new_value", 9);

    EXPECT_EQ(s.size(), 9u);
    EXPECT_STREQ(s.c_str(), "new_value");
}

TEST(SecureString, AssignNullPointerIsEmpty)
{
    SecureString s;
    s.assign(nullptr, 0);
    EXPECT_TRUE(s.empty());
}

TEST(SecureString, ConstructFromCStr)
{
    SecureString s("hello");
    EXPECT_EQ(s.size(), 5u);
    EXPECT_STREQ(s.c_str(), "hello");
}

TEST(SecureString, MoveLeavesSourceEmpty)
{
    SecureString src("secret");
    SecureString dst(std::move(src));

    EXPECT_EQ(dst.size(), 6u);
    EXPECT_STREQ(dst.c_str(), "secret");
    EXPECT_TRUE(src.empty());
}

TEST(SecureString, MoveAssignmentLeavesSourceEmpty)
{
    SecureString src("secret");
    SecureString dst;
    dst.assign("placeholder", 11);
    dst = std::move(src);

    EXPECT_EQ(dst.size(), 6u);
    EXPECT_STREQ(dst.c_str(), "secret");
    EXPECT_TRUE(src.empty());
}

TEST(SecureString, CStrIsNulTerminatedAfterBinaryData)
{
    // Even with embedded NULs the returned c_str must be NUL-terminated
    // (consumer treats it as a C string).
    const char raw[] = {'a', 'b', 'c'};
    SecureString s;
    s.assign(raw, sizeof(raw));
    const char *p = s.c_str();
    EXPECT_EQ(p[3], '\0');
}
