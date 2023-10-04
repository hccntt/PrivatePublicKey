using System.Web.Mvc;
using WebApp.Helpers;

namespace WebApp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            //var currentMethod = System.Reflection.MethodBase.GetCurrentMethod();
            //string strLog = $"[{currentMethod.DeclaringType.Namespace}][{currentMethod.ReflectedType.Name}][{currentMethod.Name}]: ";
            ////string msgResult = string.Empty, username = string.Empty;
            //log.Info($"{strLog} Begin");

            string plainText = @"Connect with me on linkedin: https://www.linkedin.com/in/dziwoki";

            string cihperText = RsaHelper.encrypt(plainText);
            string decryptedCipherText = RsaHelper.decrypt(cihperText);

            //log.Info($"Encrypted text: {cihperText}");
            //log.Info($"Decrypted text {decryptedCipherText}. Encryption/Decryption was correct {(plainText == decryptedCipherText).ToString()}");

            //log.Info($"{strLog} End");
            ViewBag.Encrypted = cihperText;
            ViewBag.Decrypted = decryptedCipherText;
            //ViewBag.Correct = string.Format("{0}", (plainText == decryptedCipherText).ToString());
            ViewBag.Correct = (plainText == decryptedCipherText).ToString();

            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}