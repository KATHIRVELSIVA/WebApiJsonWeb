using JWTTokenWebApiTest.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTTokenWebApiTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public UserController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }


        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(UserRolesModel.ADMIN);
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(UserRolesModel.OWNER);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(UserRolesModel.USER);
            if (isAdminRoleExists && isOwnerRoleExists && isUserRoleExists)
            {
                return Ok("Roles seeding is already done");
            }
            await _roleManager.CreateAsync(new IdentityRole(UserRolesModel.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(UserRolesModel.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(UserRolesModel.USER));

            return Ok("Role seeding done successfully");
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel regiterUser)
        {
            var isExistsEmail = await _userManager.FindByEmailAsync(regiterUser.Email);
            if (isExistsEmail != null)
            {
                return BadRequest("User Email is already exists");
            }
            IdentityUser newUser = new IdentityUser()
            {
                Email = regiterUser.Email,
                UserName = regiterUser.UserName,
                PasswordHash = regiterUser.Password,
                SecurityStamp = Guid.NewGuid().ToString(),
            };
            var createUserResult = await _userManager.CreateAsync(newUser, regiterUser.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Because ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += " " + error.Description;
                }
                return BadRequest(errorString);
            }
            //Add a default user role to all users
            await _userManager.AddToRoleAsync(newUser, UserRolesModel.USER);

            return Ok("User created successfully");
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginUser)
        {
            var User = await _userManager.FindByEmailAsync(loginUser.Email);
            if (User == null)
            {
                return Unauthorized("Invalid Credentials Email");
            }

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(User, loginUser.Password);
            if (isPasswordCorrect != true)
            {
                return Unauthorized("Invalid Credentials Password");
            }
            var userRoles = await _userManager.GetRolesAsync(User);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,User.UserName),
                new Claim(ClaimTypes.NameIdentifier,User.Id),
                new Claim("JWTID",Guid.NewGuid().ToString())
            };
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            var token = GenerateNewJsonWebToken(authClaims);
            return Ok(token);

        }

        private string GenerateNewJsonWebToken(List<Claim> authClaims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(10),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );
            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;
        }


    }
}
