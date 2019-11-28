using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace SimpleJwtTokenValidation
{
    public class JwtSecurityConfiguration
    {
        public JwtSecurityConfiguration(string sharedSecretKey)
        {
            if (string.IsNullOrEmpty(sharedSecretKey)) throw new ArgumentNullException(nameof(sharedSecretKey));

            var sharedSymetricKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(sharedSecretKey));

            IssuerSigningKeys = new List<SymmetricSecurityKey>()
            {
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(sharedSecretKey))
            };

            SigningCredentials = new SigningCredentials(sharedSymetricKey, SecurityAlgorithms.HmacSha256);
        }
        public List<SymmetricSecurityKey> IssuerSigningKeys { get; private set; }
        public SigningCredentials SigningCredentials { get; private set; }
    }
}