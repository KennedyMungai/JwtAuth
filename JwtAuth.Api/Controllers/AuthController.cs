using JwtAuth.Api.Models;
using Microsoft.AspNetCore.Mvc;
using JwtAuth.Api.Models.Dtos;
using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace JwtAuth.Api.Controllers;


[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    public static User user = new();
    private readonly IConfiguration _config;

    public AuthController(IConfiguration config)
    {
        _config = config;
    }

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register([FromBody] UserDto userInfo)
    {
        CreatePasswordHash(userInfo.Password, out byte[] passwordHash, out byte[] passwordSalt);
        user.UserName = userInfo.UserName;
        user.PasswordHash = passwordHash;
        user.PasswordSalt = passwordSalt;

        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<string>> Login([FromBody] UserDto userInfo)
    {
        if (user.UserName != userInfo.UserName)
        {
            return Unauthorized("The username or password given is incorrect");
        }

        if (VerifyPasswordHash(userInfo.Password, user.PasswordHash, user.PasswordSalt) is false)
        {
            return Unauthorized("The username or password given is incorrect");
        }

        string token = CreateToken(user);

        return Ok(token);
    }


    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using var hmac = new HMACSHA512();
        passwordSalt = hmac.Key;
        passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
    }

    private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
    {
        using var hmac = new HMACSHA512(passwordSalt);
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        return computedHash.SequenceEqual(passwordHash);
    }

    private string CreateToken(User user)
    {
        List<Claim> claims = new()
        {
            new Claim(ClaimTypes.Name, user.UserName)
        };

        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(1), signingCredentials: creds);

        string jwt = new JwtSecurityTokenHandler().WriteToken(token);

        return jwt;
    }
}