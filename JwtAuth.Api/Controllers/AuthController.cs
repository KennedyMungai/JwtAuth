using JwtAuth.Api.Models;
using Microsoft.AspNetCore.Mvc;
using JwtAuth.Api.Models.Dtos;
using System.Security.Cryptography;

namespace JwtAuth.Api.Controllers;


[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    public static User user = new();

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register([FromBody] UserDto userInfo)
    {
        CreatePasswordHash(userInfo.Password, out byte[] passwordHash, out byte[] passwordSalt);
        user.UserName = userInfo.UserName;
        user.PasswordHash = passwordHash;
        user.PasswordSalt = passwordSalt;

        return Ok(user);
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using var hmac = new HMACSHA512();
        passwordSalt = hmac.Key;
        passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
    }
}