using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace EmployeeManagementCoreApp.Helper
{
    public class NotificationSender
    {
        public static void SendEmail(string Email, string Message)
        {
            if (string.IsNullOrWhiteSpace(Email))
            {
                throw new ArgumentException("Email field is required", nameof(Email));
            }

            try
            {
                var credentials = new NetworkCredential("rahuljaiswalstryker@gmail.com", "Pari@123");

                var mail = new MailMessage()
                {
                    From = new MailAddress("noreply@employeeManagement.com"),
                    Subject = "EmployeeManagement Portal : Confirm Your Email Address",
                    Body = Message
                };
                mail.IsBodyHtml = true;
                mail.To.Add(new MailAddress(Email));

                var client = new SmtpClient()
                {
                    Port = 587,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Host = "smtp.gmail.com",
                    EnableSsl = true,
                    Credentials = credentials
                };
                client.Send(mail);
            }
            catch (System.Exception e)
            {
                Debug.WriteLine(e.Message);
            }
        }

        public static async Task<MessageResource> SendOTP(string number)
        {
            try
            {
                Random random = new Random();
                int value = random.Next(10000);

                var accountSid = "AC84f610897dd8f9436e340ffaf247dc4d";
                var authToken = "695a218f27a018030b6b7106dcd3b9f1";

                TwilioClient.Init(accountSid, authToken);

                MessageResource messageResource =  await MessageResource.CreateAsync(
                  to: new PhoneNumber("+91"+number),
                  from: new PhoneNumber("+12017332346"),
                  body: "OTP for EmployeeManagementCoreApp : " + value);

                return messageResource;
            }
            catch(Exception ex)
            {
                throw;
            }
        }
    }
}