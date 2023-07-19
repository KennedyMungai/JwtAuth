namespace JwtAuth.Api.Models.Dtos;

public class UserRegister
{
    public string UserName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}