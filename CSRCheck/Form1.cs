using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using CERTENROLLLib;
using CERTCLILib;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.RegularExpressions;
using System.Net;
using System.Diagnostics;

namespace CSRCheck
{
    public partial class Form1 : Form
    {
        private CX509CertificateRequestPkcs10 oRequestInterface = null;

        private const string XCN_OID_SUBJECT_ALT_NAME2 = "2.5.29.17";
        private const string XCN_OID_ENHANCED_KEY_USAGE = "2.5.29.37";
        private const string XCN_OID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

        private const string XCN_OID_KEYALGORITHM_RSA = "1.2.840.113549.1.1.1";
        private const string XCN_OID_KEYALGORITHM_ECC = "1.2.840.10045.2.1";

        private readonly static string[] definedRDNs = { "C", "S", "L", "O", "OU", "CN", "E", "DC" };
        private readonly static string[] ISO3166CountryCodes = {
            "AD","AE","AF","AG","AI","AL","AM","AO","AQ","AR","AS","AT","AU","AW",
            "AX","AZ","BA","BB","BD","BE","BF","BG","BH","BI","BJ","BL","BM","BN",
            "BO","BQ","BR","BS","BT","BV","BW","BY","BZ","CA","CC","CD","CF","CG",
            "CH","CI","CK","CL","CM","CN","CO","CR","CU","CV","CW","CX","CY","CZ",
            "DE","DJ","DK","DM","DO","DZ","EC","EE","EG","EH","ER","ES","ET","FI",
            "FJ","FK","FM","FO","FR","GA","GB","GD","GE","GF","GG","GH","GI","GL",
            "GM","GN","GP","GQ","GR","GS","GT","GU","GW","GY","HK","HM","HN","HR",
            "HT","HU","ID","IE","IL","IM","IN","IO","IQ","IR","IS","IT","JE","JM",
            "JO","JP","KE","KG","KH","KI","KM","KN","KP","KR","KW","KY","KZ","LA",
            "LB","LC","LI","LK","LR","LS","LT","LU","LV","LY","MA","MC","MD","ME",
            "MF","MG","MH","MK","ML","MM","MN","MO","MP","MQ","MR","MS","MT","MU",
            "MV","MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI","NL","NO","NP",
            "NR","NU","NZ","OM","PA","PE","PF","PG","PH","PK","PL","PM","PN","PR",
            "PS","PT","PW","PY","QA","RE","RO","RS","RU","RW","SA","SB","SC","SD",
            "SE","SG","SH","SI","SJ","SK","SL","SM","SN","SO","SR","SS","ST","SV",
            "SX","SY","SZ","TC","TD","TF","TG","TH","TJ","TK","TL","TM","TN","TO",
            "TR","TT","TV","TW","TZ","UA","UG","UM","US","UY","UZ","VA","VC","VE",
            "VG","VI","VN","VU","WF","WS","YE","YT","ZA","ZM","ZW"
        };
        private const int maxLengthforRDN = 64;
        private const int maxRecommendedSANs = 10;
        
        // have to research if an upper Limit exists
        private const int maxSANs = 255;
        private const int minRecommendedKeyLength = 2048;
        private const int maxRecommendedKeyLength = 4096;



        public Form1()
        {
            InitializeComponent();
        }

        public class CertificateRequestValidationResult
        {
            public bool Success { get; set; }
            public CX509CertificateRequestPkcs10 RequestInterface { get; set; }
        }

        public static class SeverityClass
        {
            public static readonly int INFORMATIVE = 0;
            public static readonly int LOW = 1;
            public static readonly int WARNING = 2;
            public static readonly int SEVERE = 3;
        }

        public void ResetUserInterface()
        {
            textBox1.Clear();
            textBox1.BackColor = SystemColors.Control;

            dataGridView1.BackgroundColor = SystemColors.AppWorkspace;

            dataGridView1.Rows.Clear();
            dataGridView2.Rows.Clear();
            dataGridView3.Rows.Clear();
            dataGridView4.Rows.Clear();

            button1.Enabled = false;
        }

        public void AddWarning (int severity, string description)
        {

            foreach (DataGridViewRow dgvr in dataGridView3.Rows)
            {
                if (dgvr.Cells[1].Value.ToString().Equals(description))
                {
                    // Exit if we already have the same message
                    return;
                }
            }

            Color ForeColor = SystemColors.ControlText;
            Color BackColor = Color.White;

            var row = new string[2];

            switch (severity)
            {
                case 0:
                    row[0] = "Information";
                    ForeColor = Color.DarkBlue;
                    BackColor = Color.White;
                    break;

                case 1:
                    row[0] = "Niedrig";
                    ForeColor = Color.DarkBlue;
                    BackColor = Color.White;
                    break;

                case 2:
                    row[0] = "Warnung";
                    ForeColor = Color.Black;
                    BackColor = Color.Yellow;
                    break;

                case 3:
                    row[0] = "Schwerwiegend";
                    ForeColor = Color.White;
                    BackColor = Color.Red;
                    break;
            }

            row[1] = description;

            dataGridView3.Rows.Add(row);

            dataGridView3.Rows[dataGridView3.Rows.Count - 1].Cells[0].Style.Font = new Font(SystemFonts.DefaultFont, FontStyle.Bold);
            dataGridView3.Rows[dataGridView3.Rows.Count - 1].Cells[0].Style.ForeColor = ForeColor;
            dataGridView3.Rows[dataGridView3.Rows.Count - 1].Cells[0].Style.BackColor = BackColor;

            dataGridView3.CurrentCell = null;
        }

        private void setStatus(string message)
        {
            toolStripStatusLabel1.Text = message;
            Application.DoEvents();
        }

        public bool CheckForBinary(string filepath)
        {

            Stream objStream = new FileStream(filepath, FileMode.Open, FileAccess.Read);
            bool bFlag = true;

            // Iterate through stream & check ASCII value of each byte.
            for (int nPosition = 0; nPosition < objStream.Length; nPosition++)
            {
                int a = objStream.ReadByte();

                if (!(a >= 0 && a <= 127))
                {
                    break; // Binary File
                }
                else if (objStream.Position == (objStream.Length))
                {
                    bFlag = false; // Text File
                }
            }
            objStream.Dispose();

            return bFlag;
        }

        private void DumpCsr ()
        {
            string sTempFileName1 = Path.GetTempFileName();
            string sTempFileName2 = Path.GetTempFileName();

            File.WriteAllText(sTempFileName1, oRequestInterface.RawData);

            try
            {
                var oProcess1 = new System.Diagnostics.Process();
                oProcess1.StartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                oProcess1.StartInfo.FileName = "cmd.exe";
                oProcess1.StartInfo.Arguments = "/c certutil -dump " + sTempFileName1 + " > " + sTempFileName2;
                oProcess1.Start();
                oProcess1.WaitForExit();

                if (oProcess1.ExitCode == 0)
                {
                    try
                    {
                        var oProcess2 = new System.Diagnostics.Process();
                        oProcess2.StartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Normal;
                        oProcess2.StartInfo.FileName = "notepad.exe";
                        oProcess2.StartInfo.Arguments = sTempFileName2;
                        oProcess2.Start();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                else
                {
                    // Show Error Message
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            File.Delete(sTempFileName1);
        }

        private void InspectCsr()
        {
            bool hasEmptyCN = false;
            string SubjectName = null;

            // Identify Public Key Algorithm
            // Then process Key Length
            switch (oRequestInterface.PublicKey.Algorithm.Value.ToString())
            {
                case XCN_OID_KEYALGORITHM_ECC:

                    AddWarning(SeverityClass.INFORMATIVE, "The CSR is using Elliptic Curve Cryptography (ECC) Keys. This may cause compatibility issues.");
                    textBox1.BackColor = Color.Yellow;

                    break;

                case XCN_OID_KEYALGORITHM_RSA:
                default:

                    if (oRequestInterface.PublicKey.Length < minRecommendedKeyLength)
                    {
                        AddWarning(SeverityClass.WARNING, "Key Length is less than " + minRecommendedKeyLength.ToString() + " Bits. This is not recommended due to security reasons.");
                        textBox1.BackColor = Color.Yellow;
                    }

                    if (oRequestInterface.PublicKey.Length > maxRecommendedKeyLength)
                    {
                        AddWarning(SeverityClass.INFORMATIVE, "Key Length is higher than " + maxRecommendedKeyLength.ToString() + " Bits. This may cause compatibility issues.");
                        textBox1.BackColor = Color.Yellow;
                    }

                    break;
            }

            textBox1.Text = oRequestInterface.PublicKey.Length.ToString();

            // Process Subject

            // Handle the case of an Empty Subject
            try
            {
                SubjectName = oRequestInterface.Subject.Name.ToString();
            }
            catch
            {
                // nothing
            }

            if (SubjectName != null)
            {

                string[] lines = SubjectName.Split(',');

                foreach (string line in lines)
                {
                    string[] row = line.TrimStart().Split('=');

                    dataGridView2.Rows.Add(row);
                    dataGridView2.CurrentCell = null;

                    // Check if the Common Name (CN) is empty and remember this for the Inspection of the SAN extension
                    if ((row[0] == "CN") && (row[1] == ""))
                    {
                        hasEmptyCN = true;
                    }

                    // Check if the "CN" RDN contains a Wildcard
                    if ((row[0] == "CN") && row[1].StartsWith("*."))
                    {
                        AddWarning(SeverityClass.WARNING, "The usage of Wildcard Certificates is discouraged!");
                        dataGridView2.Rows[dataGridView2.Rows.Count - 1].DefaultCellStyle.BackColor = Color.Yellow;
                    }

                    // Check if the "C" RDN is a valid to ISO3166 Country Code
                    if ((row[0] == "C") && !(ISO3166CountryCodes.Contains(row[1])))
                    {
                        AddWarning(SeverityClass.WARNING, "The value " + row[0] + "=" + row[1] + " is no valid ISO 3166 Country Code!");
                        dataGridView2.Rows[dataGridView2.Rows.Count - 1].DefaultCellStyle.BackColor = Color.Yellow;
                    }

                    // Check if the RDNs content exceeds 64 Characters
                    if (row[1].Length > maxLengthforRDN)
                    {
                        AddWarning(SeverityClass.WARNING, "The value " + row[0] + " Relative Distringuished Name (RDN) exceeds the recommended Maximum of " + maxLengthforRDN.ToString() + " Characters!");
                        dataGridView2.Rows[dataGridView2.Rows.Count - 1].DefaultCellStyle.BackColor = Color.Yellow;
                    }

                    // Check for non-defined RDNs
                    if (!(definedRDNs.Contains(row[0])))
                    {
                        AddWarning(SeverityClass.WARNING, "The " + row[0] + " Relative Distringuished Name (RDN) is not defined!");
                        dataGridView2.Rows[dataGridView2.Rows.Count - 1].DefaultCellStyle.BackColor = Color.Yellow;
                    }

                    // Check if a RDN appears more than once in the CSR
                    foreach (string rdn in definedRDNs)
                    {

                        int rdncount = new Regex(Regex.Escape(rdn + "=")).Matches(SubjectName).Count;
                        if ((row[0] == rdn) && (rdncount > 1))
                        {
                            AddWarning(SeverityClass.WARNING, "More than one RDN of Type " + rdn + " found in the Certificate Subject!");
                            dataGridView2.Rows[dataGridView2.Rows.Count - 1].DefaultCellStyle.BackColor = Color.Yellow;
                        }

                    }

                }

            }

            // Process SANs

            bool rfc2818sanfound = false;
            bool isSSLcapable = false;

            foreach (IX509Extension extension in oRequestInterface.X509Extensions)
            {
                // Eumerate all the Extensions of the CSR
                switch (extension.ObjectId.Value)
                {

                    case XCN_OID_ENHANCED_KEY_USAGE:

                        var ekuext = new CX509ExtensionEnhancedKeyUsage();

                        ekuext.InitializeDecode(
                            EncodingType.XCN_CRYPT_STRING_BASE64,
                            extension.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)
                        );

                        foreach (CObjectId oid in ekuext.EnhancedKeyUsage)
                        {
                            var row = new string[2];
                            if (oid.Value.ToString() == XCN_OID_PKIX_KP_SERVER_AUTH)
                            {
                                isSSLcapable = true;
                            }
                            row[0] = oid.Value.ToString();
                            row[1] = oid.FriendlyName;
                            dataGridView4.Rows.Add(row);
                            dataGridView4.CurrentCell = null;

                        }

                        break;

                    case XCN_OID_SUBJECT_ALT_NAME2:

                        var sanext = new CX509ExtensionAlternativeNames();

                        sanext.InitializeDecode(
                            EncodingType.XCN_CRYPT_STRING_BASE64,
                            extension.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)
                            );

                        foreach (IAlternativeName san in sanext.AlternativeNames)
                        {
                            var row = new string[2];
                            bool markrow = false;

                            // To Do: Implement all Encoding Types
                            switch (san.Type)
                            {
                                case AlternativeNameType.XCN_CERT_ALT_NAME_OTHER_NAME:
                                    // The name consists of an object identifier (OID) and a byte array that contains the name value.
                                    row[0] = "Other Name";
                                    row[1] = "not implemented yet";
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME:
                                    // The name is an email address such as someone@example.com.
                                    row[0] = "RFC822 Name";
                                    row[1] = san.strValue;
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME:
                                    row[0] = "DNS Name";
                                    row[1] = san.strValue;
                                    rfc2818sanfound = true;
                                    if (san.strValue.StartsWith("*."))
                                    {
                                        AddWarning(SeverityClass.WARNING, "The usage of Wildcard Certificates is discouraged!");
                                        markrow = true;
                                    }
                                    if (san.strValue.StartsWith("http://") || san.strValue.StartsWith("https://"))
                                    {
                                        AddWarning(SeverityClass.SEVERE, "The DNS Name Subject Alternative Name (SAN) contains an URL instead of a Host Name, which will cause the Certificate to be treated as invalid by a Browser.");
                                        markrow = true;
                                    }
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_X400_ADDRESS:
                                    row[0] = "X400 Address";
                                    row[1] = "not implemented yet";
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_DIRECTORY_NAME:
                                    // The name is an X.500 directory name
                                    row[0] = "Directory Name";
                                    row[1] = san.strValue;
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_EDI_PARTY_NAME:
                                    row[0] = "EDI Party Name";
                                    row[1] = "not implemented yet";
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_URL:
                                    row[0] = "URL";
                                    row[1] = "not implemented yet";
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS:
                                    // The name is an Internet Protocol (IP) address in dotted decimal format 123.456.789.123.
                                    row[0] = "IP Address";
                                    
                                    string b64ip = san.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64);
                                    IPAddress add = new IPAddress(Convert.FromBase64String(b64ip));
                                    rfc2818sanfound = true;

                                    row[1] = add.ToString();

                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_REGISTERED_ID:
                                    row[0] = "Registered ID";
                                    row[1] = "not implemented yet";
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_GUID:
                                    row[0] = "GUID";
                                    row[1] = "not implemented yet";
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME:
                                    row[0] = "User Principle Name";
                                    row[1] = san.strValue;
                                    break;

                                case AlternativeNameType.XCN_CERT_ALT_NAME_UNKNOWN:
                                    // The name type is not identified.

                                default:
                                    row[0] = "unknown";
                                    break;
                            }

                            dataGridView1.Rows.Add(row);
                            dataGridView1.CurrentCell = null;

                            if (markrow)
                            {
                                dataGridView1.Rows[dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = Color.Yellow;
                            }

                        }

                        // Warn if a CSR contains a lot of SANs
                        if (sanext.AlternativeNames.Count > maxRecommendedSANs)
                        {
                            AddWarning(SeverityClass.WARNING, "This certificate request contains a lot of Subject Alternative Names!");
                            foreach (DataGridViewRow dgvr in dataGridView1.Rows)
                            {
                                dgvr.DefaultCellStyle.BackColor = Color.Yellow;
                            }
                        }

                        // Throw severe Error if Number of SANs exceeds an upper Limit (if any is defined by RFC...?)
                        if (sanext.AlternativeNames.Count > maxSANs)
                        {
                            AddWarning(SeverityClass.SEVERE, "This certificate request contains more than " + maxSANs + " Subject Alternative Names!");
                            foreach (DataGridViewRow dgvr in dataGridView1.Rows)
                            {
                                dgvr.DefaultCellStyle.BackColor = Color.Yellow;
                            }
                        }

                        break;

                }

            }

            if ((isSSLcapable == true) && (rfc2818sanfound == false))
            {
                if (hasEmptyCN == true)
                {
                    AddWarning(SeverityClass.SEVERE, "Neither a Common Name nor a Subject Alternative Name (SAN) of type DNS name found despite this Certificate contains the Server Authentication Enhanced Key Usage! The resulting Certificate won't get accepted by most current Browsers!");
                }
                AddWarning(SeverityClass.WARNING, "No Subject Alternative Name (SAN) of type DNS Name found despite this Certificate contains the Server Authentication Enhanced Key Usage! The resulting Certificate won't get accepted by most current Browsers!");
                dataGridView1.BackgroundColor = Color.Yellow;
            }
        }

        public CertificateRequestValidationResult OpenCertificateRequest(string reqFilePath)
        {
            
            var result = new CertificateRequestValidationResult();
            string sRawCertificateRequest = null;


            var oRequestInterfacePkcs10 = new CX509CertificateRequestPkcs10();
            var oRequestInterfaceCmc = new CX509CertificateRequestCmc();

            // Convert to BASE64 if it is a DER-encoded (Binary) CSR
            if (CheckForBinary(reqFilePath))
            {
                byte[] bRawCertificateRequest;
                bRawCertificateRequest = File.ReadAllBytes(reqFilePath);
                sRawCertificateRequest = Convert.ToBase64String(bRawCertificateRequest);
            }
            else
            {
                sRawCertificateRequest = File.ReadAllText(reqFilePath);
            }

            try
            {

                oRequestInterfaceCmc.InitializeDecode(sRawCertificateRequest, EncodingType.XCN_CRYPT_STRING_BASE64_ANY);
                IX509CertificateRequest innerreq = oRequestInterfaceCmc.GetInnerRequest(InnerRequestLevel.LevelInnermost);

                switch (innerreq.Type)
                {
                    case X509RequestType.TypePkcs10:
                        sRawCertificateRequest = innerreq.get_RawData();
                        break;
                }

            }
            catch
            {
                //
            }

            try
            {
                oRequestInterfacePkcs10.InitializeDecode(sRawCertificateRequest, EncodingType.XCN_CRYPT_STRING_BASE64_ANY);

                oRequestInterfacePkcs10.CheckSignature();

                result.RequestInterface = oRequestInterfacePkcs10;
                result.Success = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "The Certificate Signing Request could not be verified. Please ensure that you select a file containing a valid CSR (" + ex.Message + ").",
                    "Error validating the Certificate Signing Request",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                    );
                result.Success = false;
            }

            return result;

        }

        private void cmdInspect_Click(object sender, EventArgs e)
        {
            string sRequestFilePath;
            var oOpenFileDialog1 = new OpenFileDialog();
            oOpenFileDialog1.Title = "Select Certificate Signing Request to inspect";
            oOpenFileDialog1.Filter = "X.509 CSR (*.req, *.csr, *.txt)|*.req;*.csr;*.txt|All Files|*.*";

            if (oOpenFileDialog1.ShowDialog() == DialogResult.OK)
            {
                ResetUserInterface();

                sRequestFilePath = oOpenFileDialog1.FileName;
                oOpenFileDialog1.Dispose();

                var oCsrValidationResult = OpenCertificateRequest(sRequestFilePath);
                if (oCsrValidationResult.Success)
                {
                    oRequestInterface = oCsrValidationResult.RequestInterface;
                    setStatus(sRequestFilePath);
                    InspectCsr();
                    button1.Enabled = true;
                }
                else
                {
                    return;
                }

            }

        }

        private void button1_Click(object sender, EventArgs e)
        {
            DumpCsr();
        }

    }
}
