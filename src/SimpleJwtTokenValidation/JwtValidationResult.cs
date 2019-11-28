using System.Security.Claims;

namespace SimpleJwtTokenValidation
{
    public class JwtValidationResult
    {
        public bool IsSuccess { get; set; }
        public ClaimsPrincipal Principal { get; set; }
        public string ErrorType { get; set; }
        public string ErrorMessage { get; set; }
    }
}