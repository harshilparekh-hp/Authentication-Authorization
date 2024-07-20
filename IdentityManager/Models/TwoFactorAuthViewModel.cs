namespace IdentityManager.Models
{
    public class TwoFactorAuthViewModel
    {
        // used to login
        public string Code{ get; set; }

        //used to register/signup
        public string? Token { get; set; }

        public string? QRCodeUrl { get; set; }
    }
}
