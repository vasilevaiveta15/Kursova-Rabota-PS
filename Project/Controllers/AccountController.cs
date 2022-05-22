using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNetCore.Mvc;
using Project.Models;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace Project.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;
        private ApplicationDbContext namedTemplate = new ApplicationDbContext();

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }


        //
        // POST: /Account/Login
        [System.Web.Mvc.HttpPost]
        [AllowAnonymous]
        public async Task<String> Login([FromBody] Login model)
        {
            if (null == model.UserName)
            {
                return "UserName must not be empty!";
            }
            else if (null == model.Password)
            {
                return "Password must not be empty!";
            }

            var result = await SignInManager.PasswordSignInAsync(model.UserName, model.Password, true, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return "Successful Login";
                case SignInStatus.LockedOut:
                    return "Locked";
                default:
                    return "Invalid login attempt.";
            }
        }

        public async Task<String> Login()
        {
            return "You are not ADMIN!";
        }

        // POST: /Account/Register
        [System.Web.Mvc.HttpPost]
        [AllowAnonymous]
        public async Task<String> Register(Register model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.UserName, Email = model.Email, FacultyNumber = model.FacultyNumber };
                var result = await UserManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);


                    namedTemplate.Database.ExecuteSqlCommand("INSERT INTO dbo.AspNetUserRoles (UserId,RoleId) VALUES(@UserId,3)", new SqlParameter("@UserId", user.Id));

                    return "Register Successfuly";
                }
            }

            if (null == model.Email)
            {
                return "Email must not be empty!";
            }
            else if (!model.Email.Contains("@"))
            {
                return "The email must contain @!";
            }
            else if (null == model.Password)
            {
                return "Password must not be empty!";
            }
            else if (model.Password.Length < 6)
            {
                return "Password length must be 6 or more!";
            }
            else if (null == model.ConfirmPassword)
            {
                return "Password Confirm must not be empty!";
            }
            else if (model.ConfirmPassword.Length < 6)
            {
                return "Password length must be 6 or more!";
            }
            else if (!String.Equals(model.Password, model.ConfirmPassword))
            {
                return "Password don't match!";
            }

            return "Register Failed";
        }

        [System.Web.Mvc.HttpPost]
        [Authorize(Roles = "ADMIN")]
        public async Task<String> ChangeRole(RoleChange roleChange)
        {

            if (!(roleChange.role.Equals("PROFESOR") || roleChange.role.Equals("INSPECTOR") || roleChange.role.Equals("STUDENT") || roleChange.role.Equals("ADMIN")))
            {
                return "Invalid role name! Choose From: PROFESOR,INSPECTOR,STUDENT,ADMIN";
            }
            else if (null == roleChange.username)
            {
                return "Username must not be empty!";
            }
            else if (null == roleChange.role)
            {
                return "Role must not be empty!";
            }

            String userId = namedTemplate.Database.SqlQuery<String>("SELECT Id FROM dbo.AspNetUsers WHERE UserName = @UserName", new SqlParameter("UserName", roleChange.username))
                       .FirstOrDefault();
            if (null == userId)
            {
                return "There is not user with that username!";
            }

            String roleId = namedTemplate.Database.SqlQuery<String>("SELECT Id FROM dbo.AspNetRoles WHERE Name = @roleName", new SqlParameter("roleName", roleChange.role))
                   .FirstOrDefault();


            namedTemplate.Database.ExecuteSqlCommand("UPDATE dbo.AspNetUserRoles SET RoleId = @roleId WHERE UserId = @userId ", new SqlParameter("roleId", roleId), new SqlParameter("userId", userId));

            return "Succesfully Role Changed!";
        }



        [Authorize(Roles = "ADMIN")]
        public async Task<String> LoadUsers()
{
            String str = "";
            foreach (var user in namedTemplate.Users)
            {
                str += "username: " + user.UserName + "email: " + user.Email + "faculty number: " + user.FacultyNumber + "\n"; 
            }

            return str;

        }







    }

}
