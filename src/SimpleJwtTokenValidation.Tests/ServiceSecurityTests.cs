using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace SimpleJwtTokenValidation.Tests
{
    public class ServiceSecurityTests
    {
        private const string TestIssuer = "iss.sample.co";
        private const string TestAudience = "aud.sample.co";
        private JwtSecurityConfiguration CommonSecurityConfiguration;

        public ServiceSecurityTests()
        {
            CommonSecurityConfiguration = new JwtSecurityConfiguration("V€ryS3cr3t!123456789");
        }
        
        [Fact]
        public void test_can_validate_token_successfully()
        {
            //Given
            var securityService = new JwtSecurityService(CommonSecurityConfiguration);
            var claims = new List<Claim>() {
                new Claim(ClaimTypes.Name, "david")
            };

            var jwtToken = CreateToken(claims, CommonSecurityConfiguration.SigningCredentials);
            var hanler = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            //When
            var result = securityService.ValidateToken(hanler, TestIssuer, TestAudience);

            //Then
            Assert.True(result.IsSuccess);

            var principal = result.Principal;
            var expectedNameClaim = principal.Claims.Where(c => c.Type == ClaimTypes.Name).FirstOrDefault();

            Assert.Equal("david", expectedNameClaim.Value);
        }

        [Fact]

        public void test_return_false_success_when_token_has_expired()
        {
            //Given
            var securityService = new JwtSecurityService(CommonSecurityConfiguration);
            var claims = new List<Claim>() { new Claim(ClaimTypes.Name, "david") };

            var jwtToken = CreateToken(claims, CommonSecurityConfiguration.SigningCredentials, 1);
            var hanler = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            //When
            Task.Delay(1000).Wait();
            var result = securityService.ValidateToken(hanler, TestIssuer, TestAudience);

            //Then
            Assert.False(result.IsSuccess);
            Assert.Equal(nameof(SecurityTokenExpiredException), result.ErrorType);
        }

        private JwtSecurityToken CreateToken(            
            IList<Claim> claims,
            DateTime notBefore,
            DateTime expires,
            SigningCredentials signingCredentials,
            string issuer = TestIssuer,
            string audience = TestAudience)
        {
            var jwtToken = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: notBefore,
                expires: expires,
                signingCredentials: signingCredentials);

            return jwtToken;
        }


        private JwtSecurityToken CreateToken(
           IList<Claim> claims,  
           SigningCredentials signingCredentials,

           int expiresInSeconds = 10,
           string issuer = TestIssuer,
           string audience = TestAudience)
        {
            return CreateToken(
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddSeconds(expiresInSeconds),
            signingCredentials,
            issuer,
            audience);
        }
    }
}
