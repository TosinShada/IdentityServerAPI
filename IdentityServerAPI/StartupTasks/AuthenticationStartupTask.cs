using IdentityServerApi.Authentication;
using IdentityServerApi.Authentication.Entities;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerApi.StartupTasks;

public class AuthenticationStartupTask(IServiceProvider serviceProvider) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = serviceProvider.CreateScope();

        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var roleNames = new[] { RoleNames.Administrator, RoleNames.PowerUser, RoleNames.User };

        foreach (var roleName in roleNames)
        {
            var roleExists = await roleManager.RoleExistsAsync(roleName);
            if (!roleExists)
            {
                await roleManager.CreateAsync(new ApplicationRole(roleName));
            }
        }

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var administratorUser = new ApplicationUser
        {
            UserName = "shardoeski@gmail.com",
            Email = "shardoeski@gmail.com",
            FirstName = "Tosin",
            LastName = "Shada"
        };

        await CheckCreateUserAsync(administratorUser, "Password@123", RoleNames.Administrator, RoleNames.User);

        async Task CheckCreateUserAsync(ApplicationUser user, string password, params string[] roles)
        {
            var dbUser = await userManager.FindByEmailAsync(user.Email);
            if (dbUser == null)
            {
                var result = await userManager.CreateAsync(user, password);
                if (result.Succeeded)
                {
                    await userManager.AddToRolesAsync(user, roles);
                }
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
