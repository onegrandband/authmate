using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace MfaE2ee
{
    public class MainForm : Form
    {
        private const string VaultPath = "mfa_vault.json";
        private MfaService _service;

        // Wizard controls
        private Panel _wizardPanel;
        private Label _wizardTitle;
        private Label _lblPassword;
        private TextBox _txtPassword;
        private Label _lblConfirm;
        private TextBox _txtConfirm;
        private Button _btnWizardNext;
        private Label _wizardStep2Title;
        private Label _lblName;
        private TextBox _txtName;
        private Label _lblIssuer;
        private TextBox _txtIssuer;
        private Label _lblSecret;
        private TextBox _txtSecret;
        private Button _btnFinish;
        private Label _lblWizardError;

        // Main dashboard controls
        private Panel _mainPanel;
        private ListBox _lstAccounts;
        private Button _btnGenerate;
        private Button _btnBackups;
        private Button _btnAddAccount;
        private Button _btnDeleteAccount;
        private Button _btnLock;
        private Label _lblStatus;

        public MainForm()
        {
            Text = "AuthMate - Encrypted MFA";
            Size = new Size(520, 420);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;

            _service = new MfaService(VaultPath);
            InitializeWizard();
            InitializeDashboard();

            Shown += MainForm_Shown;
        }

        private void InitializeWizard()
        {
            _wizardPanel = new Panel();
            _wizardPanel.Dock = DockStyle.Fill;
            _wizardPanel.Padding = new Padding(20);

            _wizardTitle = new Label();
            _wizardTitle.Text = "Welcome to AuthMate";
            _wizardTitle.Font = new Font(_wizardTitle.Font.FontFamily, 14, FontStyle.Bold);
            _wizardTitle.AutoSize = true;
            _wizardTitle.Location = new Point(20, 20);

            _lblPassword = new Label();
            _lblPassword.Text = "Create vault password:";
            _lblPassword.AutoSize = true;
            _lblPassword.Location = new Point(20, 70);

            _txtPassword = new TextBox();
            _txtPassword.PasswordChar = '*';
            _txtPassword.Width = 300;
            _txtPassword.Location = new Point(20, 95);

            _lblConfirm = new Label();
            _lblConfirm.Text = "Confirm password:";
            _lblConfirm.AutoSize = true;
            _lblConfirm.Location = new Point(20, 135);

            _txtConfirm = new TextBox();
            _txtConfirm.PasswordChar = '*';
            _txtConfirm.Width = 300;
            _txtConfirm.Location = new Point(20, 160);

            _btnWizardNext = new Button();
            _btnWizardNext.Text = "Next";
            _btnWizardNext.Width = 100;
            _btnWizardNext.Location = new Point(20, 200);
            _btnWizardNext.Click += BtnWizardNext_Click;

            _wizardStep2Title = new Label();
            _wizardStep2Title.Text = "Add your first account";
            _wizardStep2Title.Font = new Font(_wizardStep2Title.Font.FontFamily, 12, FontStyle.Bold);
            _wizardStep2Title.AutoSize = true;
            _wizardStep2Title.Location = new Point(20, 20);
            _wizardStep2Title.Visible = false;

            _lblName = new Label();
            _lblName.Text = "Account name:";
            _lblName.AutoSize = true;
            _lblName.Location = new Point(20, 70);
            _lblName.Visible = false;

            _txtName = new TextBox();
            _txtName.Width = 300;
            _txtName.Location = new Point(20, 95);
            _txtName.Visible = false;

            _lblIssuer = new Label();
            _lblIssuer.Text = "Issuer:";
            _lblIssuer.AutoSize = true;
            _lblIssuer.Location = new Point(20, 135);
            _lblIssuer.Visible = false;

            _txtIssuer = new TextBox();
            _txtIssuer.Width = 300;
            _txtIssuer.Location = new Point(20, 160);
            _txtIssuer.Visible = false;

            _lblSecret = new Label();
            _lblSecret.Text = "Base32 secret:";
            _lblSecret.AutoSize = true;
            _lblSecret.Location = new Point(20, 200);
            _lblSecret.Visible = false;

            _txtSecret = new TextBox();
            _txtSecret.Width = 400;
            _txtSecret.Location = new Point(20, 225);
            _txtSecret.Visible = false;

            _btnFinish = new Button();
            _btnFinish.Text = "Finish";
            _btnFinish.Width = 100;
            _btnFinish.Location = new Point(20, 270);
            _btnFinish.Click += BtnFinish_Click;
            _btnFinish.Visible = false;

            _lblWizardError = new Label();
            _lblWizardError.ForeColor = Color.Red;
            _lblWizardError.AutoSize = true;
            _lblWizardError.Location = new Point(20, 320);

            _wizardPanel.Controls.Add(_wizardTitle);
            _wizardPanel.Controls.Add(_lblPassword);
            _wizardPanel.Controls.Add(_txtPassword);
            _wizardPanel.Controls.Add(_lblConfirm);
            _wizardPanel.Controls.Add(_txtConfirm);
            _wizardPanel.Controls.Add(_btnWizardNext);
            _wizardPanel.Controls.Add(_wizardStep2Title);
            _wizardPanel.Controls.Add(_lblName);
            _wizardPanel.Controls.Add(_txtName);
            _wizardPanel.Controls.Add(_lblIssuer);
            _wizardPanel.Controls.Add(_txtIssuer);
            _wizardPanel.Controls.Add(_lblSecret);
            _wizardPanel.Controls.Add(_txtSecret);
            _wizardPanel.Controls.Add(_btnFinish);
            _wizardPanel.Controls.Add(_lblWizardError);

            Controls.Add(_wizardPanel);
        }

        private void InitializeDashboard()
        {
            _mainPanel = new Panel();
            _mainPanel.Dock = DockStyle.Fill;
            _mainPanel.Padding = new Padding(10);
            _mainPanel.Visible = false;

            Label title = new Label();
            title.Text = "AuthMate Dashboard";
            title.Font = new Font(title.Font.FontFamily, 14, FontStyle.Bold);
            title.AutoSize = true;
            title.Location = new Point(10, 10);

            _lstAccounts = new ListBox();
            _lstAccounts.Location = new Point(10, 50);
            _lstAccounts.Size = new Size(350, 220);
            _lstAccounts.DisplayMember = "DisplayText";
            _lstAccounts.ValueMember = "Id";

            _btnGenerate = new Button();
            _btnGenerate.Text = "Generate TOTP";
            _btnGenerate.Width = 120;
            _btnGenerate.Location = new Point(380, 50);
            _btnGenerate.Click += BtnGenerate_Click;

            _btnBackups = new Button();
            _btnBackups.Text = "View Backups";
            _btnBackups.Width = 120;
            _btnBackups.Location = new Point(380, 90);
            _btnBackups.Click += BtnBackups_Click;

            _btnAddAccount = new Button();
            _btnAddAccount.Text = "Add Account";
            _btnAddAccount.Width = 120;
            _btnAddAccount.Location = new Point(380, 140);
            _btnAddAccount.Click += BtnAddAccount_Click;

            _btnDeleteAccount = new Button();
            _btnDeleteAccount.Text = "Delete";
            _btnDeleteAccount.Width = 120;
            _btnDeleteAccount.Location = new Point(380, 180);
            _btnDeleteAccount.Click += BtnDeleteAccount_Click;

            _btnLock = new Button();
            _btnLock.Text = "Lock Vault";
            _btnLock.Width = 120;
            _btnLock.Location = new Point(380, 230);
            _btnLock.Click += BtnLock_Click;

            _lblStatus = new Label();
            _lblStatus.Text = "Vault unlocked.";
            _lblStatus.AutoSize = true;
            _lblStatus.Location = new Point(10, 290);

            _mainPanel.Controls.Add(title);
            _mainPanel.Controls.Add(_lstAccounts);
            _mainPanel.Controls.Add(_btnGenerate);
            _mainPanel.Controls.Add(_btnBackups);
            _mainPanel.Controls.Add(_btnAddAccount);
            _mainPanel.Controls.Add(_btnDeleteAccount);
            _mainPanel.Controls.Add(_btnLock);
            _mainPanel.Controls.Add(_lblStatus);

            Controls.Add(_mainPanel);
        }

        private void MainForm_Shown(object sender, EventArgs e)
        {
            if (!_service.VaultExists)
            {
                ShowWizard(true);
            }
            else
            {
                ShowLogin();
            }
        }

        private void ShowLogin()
        {
            using (LoginForm login = new LoginForm())
            {
                if (login.ShowDialog(this) != DialogResult.OK)
                {
                    Close();
                    return;
                }
                if (!_service.TryUnlock(login.Password))
                {
                    MessageBox.Show(this, "Incorrect password.", "Unlock Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    ShowLogin();
                    return;
                }
            }
            ShowDashboard();
        }

        private void ShowWizard(bool firstRun)
        {
            _wizardPanel.Visible = true;
            _mainPanel.Visible = false;
            _wizardTitle.Visible = true;
            _lblPassword.Visible = true;
            _txtPassword.Visible = true;
            _lblConfirm.Visible = true;
            _txtConfirm.Visible = true;
            _btnWizardNext.Visible = true;
            _wizardStep2Title.Visible = false;
            _lblName.Visible = false;
            _txtName.Visible = false;
            _lblIssuer.Visible = false;
            _txtIssuer.Visible = false;
            _lblSecret.Visible = false;
            _txtSecret.Visible = false;
            _btnFinish.Visible = false;
            _lblWizardError.Text = "";
            _btnWizardNext.Tag = firstRun;
        }

        private void BtnWizardNext_Click(object sender, EventArgs e)
        {
            _lblWizardError.Text = "";
            if (_txtPassword.Text.Length < 8)
            {
                _lblWizardError.Text = "Password must be at least 8 characters.";
                return;
            }
            if (_txtPassword.Text != _txtConfirm.Text)
            {
                _lblWizardError.Text = "Passwords do not match.";
                return;
            }

            _wizardTitle.Visible = false;
            _lblPassword.Visible = false;
            _txtPassword.Visible = false;
            _lblConfirm.Visible = false;
            _txtConfirm.Visible = false;
            _btnWizardNext.Visible = false;

            _wizardStep2Title.Visible = true;
            _lblName.Visible = true;
            _txtName.Visible = true;
            _lblIssuer.Visible = true;
            _txtIssuer.Visible = true;
            _lblSecret.Visible = true;
            _txtSecret.Visible = true;
            _btnFinish.Visible = true;
        }

        private void BtnFinish_Click(object sender, EventArgs e)
        {
            _lblWizardError.Text = "";
            if (string.IsNullOrWhiteSpace(_txtName.Text) ||
                string.IsNullOrWhiteSpace(_txtIssuer.Text) ||
                string.IsNullOrWhiteSpace(_txtSecret.Text))
            {
                _lblWizardError.Text = "Please fill in all fields.";
                return;
            }

            try
            {
                _service.CreateVault(_txtPassword.Text);
                _service.AddAccount(_txtName.Text.Trim(), _txtIssuer.Text.Trim(), _txtSecret.Text.Trim().Replace(" ", ""), 6, 30);
                ShowDashboard();
            }
            catch (Exception ex)
            {
                _lblWizardError.Text = "Error: " + ex.Message;
            }
        }

        private void ShowDashboard()
        {
            _wizardPanel.Visible = false;
            _mainPanel.Visible = true;
            RefreshAccountList();
        }

        private void RefreshAccountList()
        {
            _lstAccounts.Items.Clear();
            List<MfaAccount> accounts = _service.ListAccounts();
            foreach (MfaAccount account in accounts)
            {
                _lstAccounts.Items.Add(new AccountItem(account));
            }
            if (_lstAccounts.Items.Count > 0)
                _lstAccounts.SelectedIndex = 0;
        }

        private MfaAccount GetSelectedAccount()
        {
            AccountItem item = _lstAccounts.SelectedItem as AccountItem;
            if (item == null)
                return null;
            return item.Account;
        }

        private void BtnGenerate_Click(object sender, EventArgs e)
        {
            MfaAccount account = GetSelectedAccount();
            if (account == null)
            {
                MessageBox.Show(this, "Select an account first.", "Generate", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                string code = _service.GenerateCode(account.Id, null);
                MessageBox.Show(this, string.Format("Current TOTP for {0}: {1}", account.Name, code), "TOTP Code", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnBackups_Click(object sender, EventArgs e)
        {
            MfaAccount account = GetSelectedAccount();
            if (account == null)
            {
                MessageBox.Show(this, "Select an account first.", "Backups", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                List<string> codes = _service.GetBackupCodes(account.Id);
                string text = codes.Count == 0 ? "No backup codes found." : string.Join(Environment.NewLine, codes);
                MessageBox.Show(this, text, string.Format("Backup codes for {0}", account.Name), MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnAddAccount_Click(object sender, EventArgs e)
        {
            using (AddAccountForm dlg = new AddAccountForm())
            {
                if (dlg.ShowDialog(this) != DialogResult.OK)
                    return;
                try
                {
                    _service.AddAccount(dlg.AccountName, dlg.Issuer, dlg.Secret.Replace(" ", ""), 6, 30);
                    RefreshAccountList();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void BtnDeleteAccount_Click(object sender, EventArgs e)
        {
            MfaAccount account = GetSelectedAccount();
            if (account == null)
                return;
            DialogResult result = MessageBox.Show(this, string.Format("Delete account '{0}'?", account.Name), "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (result != DialogResult.Yes)
                return;
            try
            {
                _service.DeleteAccount(account.Id);
                RefreshAccountList();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnLock_Click(object sender, EventArgs e)
        {
            _service = new MfaService(VaultPath);
            _mainPanel.Visible = false;
            ShowLogin();
        }

        private class AccountItem
        {
            public MfaAccount Account { get; private set; }
            public string DisplayText { get; private set; }

            public AccountItem(MfaAccount account)
            {
                Account = account;
                DisplayText = string.Format("{0} ({1})", account.Name, account.Issuer);
            }
        }
    }

    public class LoginForm : Form
    {
        public string Password { get; private set; }

        public LoginForm()
        {
            Text = "Unlock Vault";
            Size = new Size(360, 160);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;

            Label lbl = new Label();
            lbl.Text = "Enter vault password:";
            lbl.AutoSize = true;
            lbl.Location = new Point(10, 10);

            TextBox txt = new TextBox();
            txt.PasswordChar = '*';
            txt.Width = 320;
            txt.Location = new Point(10, 35);

            Button ok = new Button();
            ok.Text = "Unlock";
            ok.DialogResult = DialogResult.OK;
            ok.Location = new Point(10, 70);

            Button cancel = new Button();
            cancel.Text = "Cancel";
            cancel.DialogResult = DialogResult.Cancel;
            cancel.Location = new Point(100, 70);

            AcceptButton = ok;
            CancelButton = cancel;

            ok.Click += (sender, e) => { Password = txt.Text; };

            Controls.Add(lbl);
            Controls.Add(txt);
            Controls.Add(ok);
            Controls.Add(cancel);
        }
    }

    public class AddAccountForm : Form
    {
        public string AccountName { get; private set; }
        public string Issuer { get; private set; }
        public string Secret { get; private set; }

        public AddAccountForm()
        {
            Text = "Add Account";
            Size = new Size(420, 240);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;

            Label lblName = new Label();
            lblName.Text = "Account name:";
            lblName.AutoSize = true;
            lblName.Location = new Point(10, 10);

            TextBox txtName = new TextBox();
            txtName.Width = 370;
            txtName.Location = new Point(10, 30);

            Label lblIssuer = new Label();
            lblIssuer.Text = "Issuer:";
            lblIssuer.AutoSize = true;
            lblIssuer.Location = new Point(10, 60);

            TextBox txtIssuer = new TextBox();
            txtIssuer.Width = 370;
            txtIssuer.Location = new Point(10, 80);

            Label lblSecret = new Label();
            lblSecret.Text = "Base32 secret:";
            lblSecret.AutoSize = true;
            lblSecret.Location = new Point(10, 110);

            TextBox txtSecret = new TextBox();
            txtSecret.Width = 370;
            txtSecret.Location = new Point(10, 130);

            Button ok = new Button();
            ok.Text = "Add";
            ok.DialogResult = DialogResult.OK;
            ok.Location = new Point(10, 170);

            Button cancel = new Button();
            cancel.Text = "Cancel";
            cancel.DialogResult = DialogResult.Cancel;
            cancel.Location = new Point(100, 170);

            AcceptButton = ok;
            CancelButton = cancel;

            ok.Click += (sender, e) =>
            {
                AccountName = txtName.Text.Trim();
                Issuer = txtIssuer.Text.Trim();
                Secret = txtSecret.Text.Trim();
            };

            Controls.Add(lblName);
            Controls.Add(txtName);
            Controls.Add(lblIssuer);
            Controls.Add(txtIssuer);
            Controls.Add(lblSecret);
            Controls.Add(txtSecret);
            Controls.Add(ok);
            Controls.Add(cancel);
        }
    }
}
