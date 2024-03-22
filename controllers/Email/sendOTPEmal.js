import nodemailer from 'nodemailer';

export const sendOTPEmail = async (email, otp, subject, footerMessage) => {
    return new Promise(async (resolve, reject) => {
        try {
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL, // your email
                    pass: process.env.APP_PASSWORD // your app password
                }
            });

            const mailOptions = {
                from: `Attract Games <${process.env.EMAIL}>`,
                to: email,
                subject: subject || 'OTP for Attract Games',
                text: `Your OTP is ${otp}`,
                html: `<h1>Your OTP is ${otp}</h1>
                ${footerMessage ? `<p>${footerMessage}</p>` : ''}`

            };

            const info = await transporter.sendMail(mailOptions);
            resolve({ success: true, message: 'OTP sent successfully' });
        } catch (error) {
            reject({ success: false, message: 'Something went wrong', error: error });
        }
    });
}

const emailConfig = {
    service: 'gmail',
    auth: {
        user: process.env.EMAIL, // your email
        pass: process.env.APP_PASSWORD // your app password
    }
};

// Function to send an email with license codes
export const sendLicenseCodeEmail = async (user, items) => {
    try {
        const transporter = nodemailer.createTransport(emailConfig);

        const mailOptions = {
            from: `Attract Games <${process.env.EMAIL}>`,
            to: user.email,
            subject: 'License Code Purchase Confirmation',
            html: `
                <h1>Hello ${user.username},</h1>
                <p>Thank you for your purchase. Below are the license codes for the games you bought:</p>
                <ul>
                    ${items.map(item => `
                        <li>
                            <strong>${item.quantity}x ${item.gameTitle}</strong><br>
                            License Codes:<br>
                            ${item.licenseKeysData.map(key => `<code>${key.key}</code>`).join('<br>')}
                        </li>
                    `).join('')}
                </ul>
                <p>Thank you for choosing Attract Games!</p>
            `,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('License code email sent successfully:', info.response);

        return { success: true, message: 'License code email sent successfully' };
    } catch (error) {
        console.error('Error sending license code email:', error);
        return { success: false, message: 'Something went wrong while sending the email', error: error };
    }
};
