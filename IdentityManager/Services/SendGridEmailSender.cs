using Microsoft.AspNetCore.Identity.UI.Services;
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Net.Mail;

namespace IdentityManager.Services
{
    public class SendGridEmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        public SendGridMailOptions Options { get; set; }
        public SendGridEmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            Options = _configuration.GetSection("SendGrid").Get<SendGridMailOptions>();
            var client = new SendGridClient(Options.ApiKey);
            var from = new EmailAddress("parekhharshil21@gmail.com", "Harshil Parekh");
            //var subject = "Sending with SendGrid is Fun";
            var to = new EmailAddress(email);
            var plainTextContent = "Hello";
            //var htmlContent = htmlMessage
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlMessage);
            var response = await client.SendEmailAsync(msg);
        }

    }
}
