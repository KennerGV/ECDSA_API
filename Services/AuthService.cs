
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

public class AuthService
{
    private readonly IConfiguration _configuration;
    private readonly ECDsaSecurityKey _ecdsaKey;

    public AuthService(IConfiguration configuration)
    {
        _configuration = configuration;

        var keyLines = _configuration.GetSection("Jwt:KeyLinesECPv").Get<string[]>();
        var privateKeyPem = string.Join("\n", keyLines);

        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(privateKeyPem);
        _ecdsaKey = new ECDsaSecurityKey(ecdsa);
    }

    public string GenerateToken(string email)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var credentials = new SigningCredentials(_ecdsaKey, SecurityAlgorithms.EcdsaSha256);

        var jwtConfig = _configuration.GetSection("Jwt");
        var token = new JwtSecurityToken(
            issuer: jwtConfig["Issuer"],
            audience: jwtConfig["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtConfig["ExpiryMinutes"])),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
