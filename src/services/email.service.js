import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

export const sendVerificationEmail = async (email, token) => {
  const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

  await transporter.sendMail({
    from: '"Ecom Verification" <ecom1ghana@gmail.com>',
    to: email,
    subject: 'Verify your email',
    html: `
      <p>Please verify your email by clicking the link below:</p>
      <a href="${verifyUrl}">Verify Email</a>
      <p>This link expires in 24 hours.</p>
    `
  });
};

export const sendAccountDeletionEmail = async (email, username) => {
  await transporter.sendMail({
    from: '"Ecom Support" <ecom1ghana@gmail.com>',
    to: email,
    subject: "Your account has been deactivated",
    text: `Hello ${username}, your account has been deactivated by an administrator.`,
  });
};