using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace SimpleJwtTokenValidation
{
    public class JwtSecurityService
    {
        const string HeaderBearer = "Bearer";

        private JwtSecurityConfiguration configuration;
        readonly ILogger<JwtSecurityService> logger;

        public JwtSecurityService(JwtSecurityConfiguration configuration) : this(configuration, null)
        {
        }

        public JwtSecurityService(JwtSecurityConfiguration configuration, ILogger<JwtSecurityService> logger)
        {
            this.configuration = configuration;
            this.logger = logger;
        }

        public JwtValidationResult ValidateToken(
            AuthenticationHeaderValue authHeaderValue,
            string issuer,
            string audience,
            bool validateLifeTime = true)
        {
            if (authHeaderValue == null) throw new ArgumentNullException(nameof(AuthenticationHeaderValue));

            if (authHeaderValue.Scheme != HeaderBearer)
                return null;

            return ValidateToken(authHeaderValue.Parameter, issuer, audience, validateLifeTime);
        }

        public JwtValidationResult ValidateToken(
            string bearerToken,
            string issuer,
            string audience,
            bool validateLifeTime = true)
        {
           var validationParameter = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidAudience = audience,
                ValidateAudience = true,
                ValidIssuer = issuer,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = validateLifeTime,
                IssuerSigningKeys = configuration.IssuerSigningKeys,
                ClockSkew = TimeSpan.Zero //default value 5 minutes
           };

            JwtValidationResult result = new JwtValidationResult();
            result.IsSuccess = false;
            

            try
            {
                var handler = new JwtSecurityTokenHandler();
                ClaimsPrincipal principal = handler.ValidateToken(bearerToken, validationParameter, out var securityToken);
                result.IsSuccess = true;
                result.Principal = principal;
            }
            catch (SecurityTokenSignatureKeyNotFoundException ex) {
                logger?.LogError(ex, nameof(SecurityTokenSignatureKeyNotFoundException));

                result.ErrorType = nameof(SecurityTokenSignatureKeyNotFoundException);
                result.ErrorMessage = ex.Message;
            }
            catch(SecurityTokenExpiredException ex) {
                logger?.LogError(ex, nameof(SecurityTokenExpiredException));

                result.ErrorType = nameof(SecurityTokenExpiredException);
                result.ErrorMessage = ex.Message;
            }
            catch (SecurityTokenException ex) {
                logger?.LogError(ex, nameof(SecurityTokenException));

                result.ErrorType = nameof(SecurityTokenException);
                result.ErrorMessage = ex.Message;
            }
            catch (Exception ex) {
                logger?.LogError(ex, "can not validate token");

                result.ErrorType = nameof(Exception);
                result.ErrorMessage = ex.Message;
            }

            return result;
        }
    }
}
;