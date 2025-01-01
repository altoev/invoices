require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { APIContracts, APIControllers } = require('authorizenet');
const SDKConstants = require('authorizenet').Constants;
const app = express();
const stripe = require('stripe')(process.env.STRIPE_SEC_KEY);
const { body, validationResult } = require('express-validator');
const { PDFDocument } = require('pdf-lib');
const fs = require('fs');
const cors = require('cors');
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Simple in-memory user for demonstration (use database in production)
const users = [{ username: 'damian', password: 'Nana1523!' }];

// Initialize sessions
app.use(
    session({
        secret: 'your-secret-key',
        resave: false,
        saveUninitialized: false,
    })
);

// Login Route
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Save user session
    req.session.user = { username };
    res.status(200).json({ message: 'Login successful' });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.status(200).json({ message: 'Logged out successfully' });
    });
});

// Middleware to Protect Routes
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.status(401).redirect('/login.html');
}

// Protect backend_invoice page
app.get('/backend_invoice', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'backend_invoice.html'));
});

mongoose.connect(process.env.MONGO_DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch((error) => {
        console.error('Error connecting to MongoDB:', error.message);
        process.exit(1); // Exit the app if the connection fails
    });

    // Middleware to serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to remove ".html" from paths
app.use((req, res, next) => {
    const filePath = path.join(__dirname, 'public', `${req.path}.html`);
    if (req.path !== '/' && !req.path.includes('.') && !req.path.endsWith('/')) {
        res.sendFile(filePath, (err) => {
            if (err) next(); // Continue if file not found
        });
    } else {
        next(); // Proceed to next middleware or route
    }
});

const InvoiceSchema = new mongoose.Schema({
    invoiceNumber: { type: String, required: true, unique: true },
    authCustomerId: { type: String, required: false },
    reservationId: { type: String, required: false },
    customerName: { type: String, required: true },
    customerEmail: { type: String, required: true },
    amount: { type: Number, required: true },
    balance: { type: Number, default: 0 },
    status: { type: String, default: 'Unpaid' },
    paidAt: { type: Date },
    payments: [
        {
            amount: { type: Number, required: true },
            paidAt: { type: Date, required: true },
            cardLast4: { type: String, required: true },
            transactionId: { type: String, required: true },
        },
    ],
    lineItems: [
        {
            category: { type: String },
            items: [{ name: { type: String }, amount: { type: Number } }],
            total: { type: Number },
        },
    ],
    subtotal: { type: Number },
    createdAt: { type: Date, default: Date.now },
});

const Invoice = mongoose.models.Invoice || mongoose.model('Invoices', InvoiceSchema);

async function generatePDF(Invoice, isReceipt = false) {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([600, 400]);
    page.drawText(isReceipt ? 'Payment Receipt' : 'Invoice', { x: 50, y: 350, size: 20 });
    page.drawText(`Invoice Number: ${invoice.invoiceNumber}`, { x: 50, y: 300 });
    page.drawText(`Customer Name: ${invoice.customerName}`, { x: 50, y: 280 });
    page.drawText(`Customer Email: ${invoice.customerEmail}`, { x: 50, y: 260 });
    page.drawText(`Amount: $${invoice.amount.toFixed(2)}`, { x: 50, y: 240 });
    page.drawText(`Status: ${invoice.status}`, { x: 50, y: 220 });
    if (isReceipt && invoice.paidAt) page.drawText(`Paid At: ${invoice.paidAt.toLocaleString()}`, { x: 50, y: 200 });
    return await pdfDoc.save();
}

// Generate PDF Helper Function
async function generatePDF(Invoice, isReceipt = false) {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([600, 400]);

    const title = isReceipt ? 'Payment Receipt' : 'Invoice';
    page.drawText(title, { x: 50, y: 350, size: 20 });
    page.drawText(`Invoice Number: ${invoice.invoiceNumber}`, { x: 50, y: 300 });
    page.drawText(`Customer Name: ${invoice.customerName}`, { x: 50, y: 280 });
    page.drawText(`Customer Email: ${invoice.customerEmail}`, { x: 50, y: 260 });
    page.drawText(`Amount: $${invoice.amount.toFixed(2)}`, { x: 50, y: 240 });
    page.drawText(`Status: ${invoice.status}`, { x: 50, y: 220 });

    if (isReceipt && Invoice.paidAt) {
        page.drawText(`Paid At: ${Invoice.paidAt.toLocaleString()}`, { x: 50, y: 200 });
    }

    const pdfBytes = await pdfDoc.save();
    return pdfBytes;
}

// Define the Invoice schema
// Ensure `Invoice` is imported properly before using it

app.post(
    '/invoices',
    [
        body('customerName').notEmpty().withMessage('Customer name is required.'),
        body('customerEmail').isEmail().withMessage('Valid email is required.'),
        body('lineItems').isArray({ min: 1 }).withMessage('At least one line item is required.'),
        body('lineItems.*.items')
            .isArray({ min: 1 })
            .withMessage('Each line item must include at least one item with valid details.')
            .bail()
            .custom((items) => {
                return items.every(
                    (item) => item.name && typeof item.name === 'string' && item.amount && item.amount > 0
                );
            })
            .withMessage('Each item must have a valid name and a positive amount.'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.error('Validation Errors:', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { customerName, customerEmail, lineItems } = req.body;

            console.log('Received Payload:', req.body);

            const invoiceNumber = `INV-${Date.now()}`;

            // Calculate subtotal and validate totals for each line item
            let subtotal = 0;
            lineItems.forEach((lineItem) => {
                if (!Array.isArray(lineItem.items) || lineItem.items.length === 0) {
                    throw new Error(`Line item "${lineItem.category || 'Unnamed'}" must have at least one valid item.`);
                }

                lineItem.total = lineItem.items.reduce((sum, item) => {
                    if (!item.name || !item.amount) {
                        throw new Error('Each item must have a valid name and amount.');
                    }
                    return sum + item.amount;
                }, 0);
                subtotal += lineItem.total;
            });

            console.log('Calculated Subtotal:', subtotal);

            // Create new invoice with balance initialized to subtotal
            const newInvoice = new Invoice({
                invoiceNumber,
                customerName,
                customerEmail,
                amount: subtotal, // Total amount based on line items
                balance: subtotal, // Set balance equal to the total amount
                lineItems,
                subtotal,
                link: `/customer_invoice.html?id=${invoiceNumber}`,
                status: 'Unpaid', // Default status
                payments: [], // Initialize an empty payments array
            });

            // Save the new invoice to the database
            await newInvoice.save();

            console.log('Invoice Created:', newInvoice);

            // Respond with the newly created invoice
            res.status(201).json(newInvoice);
        } catch (error) {
            console.error('Error creating invoice:', error.message || error);
            res.status(500).json({ error: 'An error occurred while creating the invoice.' });
        }
    }
);
app.get('/invoices', async (req, res) => {
    try {
        const invoices = await Invoice.find(); // Fetch invoices from MongoDB
        res.status(200).json(invoices); // Send invoices as a JSON response
    } catch (error) {
        console.error('Error fetching invoices:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Process Payment Endpoint
app.post('/invoices/:id/pay', async (req, res) => {
    const { cardNumber, expirationDate, cardCode, amount, billingAddress } = req.body;

    console.log('Received payment payload:', req.body);

    // Validate input
    if (!cardNumber || !expirationDate || !cardCode || !amount || amount <= 0 || !billingAddress) {
        return res.status(400).json({
            success: false,
            message: 'All payment details, billing address, and a valid amount are required.',
        });
    }

    try {
        const { id } = req.params;

        // Fetch the invoice by ID
        const invoice = await Invoice.findById(id);

        if (!invoice) {
            return res.status(404).json({
                success: false,
                message: 'Invoice not found.',
            });
        }

        if (invoice.status === 'Paid') {
            return res.status(400).json({
                success: false,
                message: 'Invoice is already fully paid.',
            });
        }

        if (amount > invoice.balance) {
            return res.status(400).json({
                success: false,
                message: 'Payment amount exceeds the outstanding balance.',
            });
        }

        // Extract the customer's name from the database
        const customerName = invoice.customerName;

        if (!customerName) {
            return res.status(500).json({
                success: false,
                message: 'Customer name is missing in the invoice record.',
            });
        }

        // Configure Authorize.Net payment
        const merchantAuthenticationType = new APIContracts.MerchantAuthenticationType();
        merchantAuthenticationType.setName(process.env.AUTHORIZE_NET_API_LOGIN_ID);
        merchantAuthenticationType.setTransactionKey(process.env.AUTHORIZE_NET_API_TRANSACTION_KEY);

        const creditCard = new APIContracts.CreditCardType();
        creditCard.setCardNumber(cardNumber);
        creditCard.setExpirationDate(expirationDate);
        creditCard.setCardCode(cardCode);

        const paymentType = new APIContracts.PaymentType();
        paymentType.setCreditCard(creditCard);

        // Add billing address and customer name
        const address = new APIContracts.CustomerAddressType();
        address.setFirstName(customerName.split(' ')[0]); // Extract first name
        address.setLastName(customerName.split(' ').slice(1).join(' ') || ''); // Extract last name
        address.setAddress(billingAddress.street);
        address.setCity(billingAddress.city);
        address.setState(billingAddress.state);
        address.setZip(billingAddress.zip);
        address.setCountry("USA"); // Default to USA, adjust as necessary

        const transactionRequest = new APIContracts.TransactionRequestType();
        transactionRequest.setTransactionType(APIContracts.TransactionTypeEnum.AUTHCAPTURETRANSACTION);
        transactionRequest.setPayment(paymentType);
        transactionRequest.setAmount(amount);
        transactionRequest.setBillTo(address);

        const createTransactionRequest = new APIContracts.CreateTransactionRequest();
        createTransactionRequest.setMerchantAuthentication(merchantAuthenticationType);
        createTransactionRequest.setTransactionRequest(transactionRequest);

        console.log('Authorize.Net request payload:', JSON.stringify(createTransactionRequest.getJSON(), null, 2));

        // Execute transaction
        const transactionResult = await new Promise((resolve, reject) => {
            const controller = new APIControllers.CreateTransactionController(createTransactionRequest.getJSON());
            controller.setEnvironment(
                process.env.AUTHORIZE_NET_ENVIRONMENT === 'production'
                    ? SDKConstants.endpoint.production
                    : SDKConstants.endpoint.sandbox
            );

            controller.execute(() => {
                const apiResponse = controller.getResponse();
                const response = new APIContracts.CreateTransactionResponse(apiResponse);

                if (response && response.getMessages().getResultCode() === APIContracts.MessageTypeEnum.OK) {
                    const transactionResponse = response.getTransactionResponse();
                    if (transactionResponse && transactionResponse.getMessages()) {
                        resolve({ success: true, transactionId: transactionResponse.getTransId() });
                    } else if (transactionResponse && transactionResponse.getErrors()) {
                        reject(new Error(transactionResponse.getErrors().getError()[0].getErrorText()));
                    } else {
                        reject(new Error('Unknown transaction error.'));
                    }
                } else {
                    const error = response.getMessages().getMessage()[0];
                    reject(new Error(error.getText()));
                }
            });
        });

        // Update invoice on success
        console.log('Payment successful with Transaction ID:', transactionResult.transactionId);

        invoice.payments.push({
            amount,
            paidAt: new Date(),
            cardLast4: cardNumber.slice(-4),
            transactionId: transactionResult.transactionId,
        });

        invoice.balance = parseFloat(invoice.balance) - parseFloat(amount);
        if (invoice.balance <= 0) {
            invoice.balance = 0;
            invoice.status = 'Paid';
            invoice.paidAt = new Date();
        }

        await invoice.save();

        return res.status(200).json({
            success: true,
            message: 'Payment successful!',
            transactionID: transactionResult.transactionId,
            invoice,
        });
    } catch (error) {
        console.error('Error processing payment: Payment Failed');
        return res.status(500).json({
            success: false,
            message: 'An error occurred while processing the payment.',
        });
    }
});

// Custom Payment Endpoint
app.post('/invoices/:id/custom-pay', async (req, res) => {
    const { cardNumber, expirationDate, cardCode, amount, billingAddress } = req.body;

    console.log('Received custom payment payload:', req.body);

    // Validate input
    if (!cardNumber || !expirationDate || !cardCode || !amount || amount <= 0 || !billingAddress) {
        return res.status(400).json({
            success: false,
            message: 'All payment details, billing address, and a valid amount are required.',
        });
    }

    try {
        const { id } = req.params;

        // Fetch the invoice by ID
        const invoice = await Invoice.findById(id);

        if (!invoice) {
            return res.status(404).json({
                success: false,
                message: 'Invoice not found.',
            });
        }

        if (invoice.status === 'Paid') {
            return res.status(400).json({
                success: false,
                message: 'Invoice is already fully paid.',
            });
        }

        if (amount > invoice.balance) {
            return res.status(400).json({
                success: false,
                message: 'Payment amount exceeds the outstanding balance.',
            });
        }

        // Configure Authorize.Net payment
        const merchantAuthenticationType = new APIContracts.MerchantAuthenticationType();
        merchantAuthenticationType.setName(process.env.AUTHORIZE_NET_API_LOGIN_ID);
        merchantAuthenticationType.setTransactionKey(process.env.AUTHORIZE_NET_API_TRANSACTION_KEY);

        const creditCard = new APIContracts.CreditCardType();
        creditCard.setCardNumber(cardNumber);
        creditCard.setExpirationDate(expirationDate);
        creditCard.setCardCode(cardCode);

        const paymentType = new APIContracts.PaymentType();
        paymentType.setCreditCard(creditCard);

        // Add billing address and customer name
        const address = new APIContracts.CustomerAddressType();
        const customerName = invoice.customerName || 'Unknown Customer';
        address.setFirstName(customerName.split(' ')[0]); // Extract first name
        address.setLastName(customerName.split(' ').slice(1).join(' ') || ''); // Extract last name
        address.setAddress(billingAddress.street);
        address.setCity(billingAddress.city);
        address.setState(billingAddress.state);
        address.setZip(billingAddress.zip);
        address.setCountry("USA"); // Default to USA, adjust as necessary

        const transactionRequest = new APIContracts.TransactionRequestType();
        transactionRequest.setTransactionType(APIContracts.TransactionTypeEnum.AUTHCAPTURETRANSACTION);
        transactionRequest.setPayment(paymentType);
        transactionRequest.setAmount(amount);
        transactionRequest.setBillTo(address);

        const createTransactionRequest = new APIContracts.CreateTransactionRequest();
        createTransactionRequest.setMerchantAuthentication(merchantAuthenticationType);
        createTransactionRequest.setTransactionRequest(transactionRequest);

        console.log('Authorize.Net request payload:', JSON.stringify(createTransactionRequest.getJSON(), null, 2));

        // Execute transaction
        const transactionResult = await new Promise((resolve, reject) => {
            const controller = new APIControllers.CreateTransactionController(createTransactionRequest.getJSON());
            controller.setEnvironment(
                process.env.AUTHORIZE_NET_ENVIRONMENT === 'production'
                    ? SDKConstants.endpoint.production
                    : SDKConstants.endpoint.sandbox
            );

            controller.execute(() => {
                const apiResponse = controller.getResponse();
                const response = new APIContracts.CreateTransactionResponse(apiResponse);

                if (response && response.getMessages().getResultCode() === APIContracts.MessageTypeEnum.OK) {
                    const transactionResponse = response.getTransactionResponse();
                    if (transactionResponse && transactionResponse.getMessages()) {
                        resolve({ success: true, transactionId: transactionResponse.getTransId() });
                    } else if (transactionResponse && transactionResponse.getErrors()) {
                        const error = transactionResponse.getErrors().getError()[0];
                        reject(new Error(error.getErrorText()));
                    } else {
                        reject(new Error('Unknown transaction error.'));
                    }
                } else {
                    const error = response.getMessages().getMessage()[0];
                    reject(new Error(error.getText()));
                }
            });
        });

        // Update invoice on success
        console.log('Custom payment successful with Transaction ID:', transactionResult.transactionId);

        invoice.payments.push({
            amount,
            paidAt: new Date(),
            cardLast4: cardNumber.slice(-4),
            transactionId: transactionResult.transactionId,
        });

        invoice.balance = parseFloat(invoice.balance) - parseFloat(amount);

        // Do not mark the invoice as fully paid unless balance is zero
        if (invoice.balance <= 0) {
            invoice.balance = 0;
            invoice.status = 'Paid';
            invoice.paidAt = new Date();
        }

        await invoice.save();

        return res.status(200).json({
            success: true,
            message: 'Custom payment successful!',
            transactionID: transactionResult.transactionId,
            balance: invoice.balance,
            status: invoice.status,
            paidAt: invoice.paidAt,
        });
    } catch (error) {
        console.error('Error processing custom payment:', error.message || error);
        return res.status(500).json({
            success: false,
            message: 'An error occurred while processing the payment.',
        });
    }
});

// Download Invoice or Receipt Endpoint
app.get('/invoices/:id/download', async (req, res) => {
    try {
        const { id } = req.params;
        const { type } = req.query;

        const invoice = await Invoice.findById(id);
        if (!invoice) return res.status(404).json({ error: 'Invoice not found' });

        const pdfBytes = await generatePDF(invoice, type === 'receipt');
        const fileName = `${type === 'receipt' ? 'Receipt' : 'Invoice'}_${invoice.invoiceNumber}.pdf`;

        res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
        res.setHeader('Content-Type', 'application/pdf');
        res.send(pdfBytes);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Fetch Invoice by ID
app.get('/invoices/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const invoice = await Invoice.findById(id);

        if (!invoice) return res.status(404).json({ error: 'Invoice not found' });

        res.json(invoice);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Authorize.Net Helper Function to Search Customer Profiles
async function getCustomerProfileByEmail(email) {
    return new Promise((resolve, reject) => {
        const merchantAuth = new APIContracts.MerchantAuthenticationType();
        merchantAuth.setName(process.env.AUTHORIZE_NET_API_LOGIN_ID);
        merchantAuth.setTransactionKey(process.env.AUTHORIZE_NET_API_TRANSACTION_KEY);

        const getRequest = new APIContracts.GetCustomerProfileIdsRequest();
        getRequest.setMerchantAuthentication(merchantAuth);

        const ctrl = new APIControllers.GetCustomerProfileIdsController(getRequest.getJSON());
        ctrl.execute(() => {
            const response = new APIContracts.GetCustomerProfileIdsResponse(ctrl.getResponse());

            if (response.getMessages().getResultCode() === APIContracts.MessageTypeEnum.OK) {
                const profileIds = response.getIds();
                // If profiles exist, fetch and validate email
                if (profileIds && profileIds.length > 0) {
                    resolve(profileIds); // Return all profile IDs (filter later)
                } else {
                    reject(new Error('No customer profiles found'));
                }
            } else {
                reject(new Error(response.getMessages().getMessage()[0].getText()));
            }
        });
    });
}

// Authorize.Net Helper Function to Create a New Customer Profile
async function createCustomerProfile(name, email) {
    return new Promise((resolve, reject) => {
        const merchantAuth = new APIContracts.MerchantAuthenticationType();
        merchantAuth.setName(process.env.AUTHORIZE_NET_API_LOGIN_ID);
        merchantAuth.setTransactionKey(process.env.AUTHORIZE_NET_API_TRANSACTION_KEY);

        const profile = new APIContracts.CustomerProfileType();
        profile.setMerchantCustomerId(email); // Unique identifier for the customer
        profile.setDescription(`Profile for ${name}`);
        profile.setEmail(email);

        const request = new APIContracts.CreateCustomerProfileRequest();
        request.setMerchantAuthentication(merchantAuth);
        request.setProfile(profile);

        const ctrl = new APIControllers.CreateCustomerProfileController(request.getJSON());
        ctrl.execute(() => {
            const response = new APIContracts.CreateCustomerProfileResponse(ctrl.getResponse());

            if (response.getMessages().getResultCode() === APIContracts.MessageTypeEnum.OK) {
                resolve(response.getCustomerProfileId());
            } else {
                reject(new Error(response.getMessages().getMessage()[0].getText()));
            }
        });
    });
}


// API Endpoint
app.post('/invoices/:invoiceNumber/customer', async (req, res) => {
    const { invoiceNumber } = req.params;
    const { email, name } = req.body;

    if (!email || !name) {
        return res.status(400).json({ error: 'Email and name are required' });
    }

    try {
        const invoice = await Invoice.findOne({ invoiceNumber });
        if (!invoice) {
            return res.status(404).json({ error: 'Invoice not found' });
        }

        let customerProfileId;
        try {
            // Attempt to fetch customer profiles
            const profiles = await getCustomerProfileByEmail(email);
            // Match the exact email if profiles exist
            if (profiles && profiles.length > 0) {
                customerProfileId = profiles[0]; // For simplicity, use the first match
            }
        } catch {
            console.log('Customer profile not found, creating a new one...');
        }

        if (!customerProfileId) {
            customerProfileId = await createCustomerProfile(name, email);
        }

        // Associate customerProfileId with the invoice
        invoice.authCustomerId = customerProfileId;
        await invoice.save();

        res.json({ success: true, message: 'Customer profile linked to invoice', customerProfileId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post('/authorize-customer', async (req, res) => {
    const { name, email } = req.body;

    if (!name || !email) {
        return res.status(400).json({ error: 'Name and email are required.' });
    }

    try {
        // Search for existing customer profile
        const customerProfileId = await getCustomerProfileByEmail(email);
        if (customerProfileId) {
            console.log(`Customer found: ${customerProfileId}`);
            return res.json({ authCustomerId: customerProfileId });
        }

        // Create a new customer profile if not found
        const newCustomerProfileId = await createCustomerProfile(name, email);
        console.log(`Customer created: ${newCustomerProfileId}`);
        return res.json({ authCustomerId: newCustomerProfileId });
    } catch (error) {
        console.error('Error interacting with Authorize.Net:', error.message);
        return res.status(500).json({ error: 'Failed to retrieve customer ID from Authorize.Net.' });
    }
});

// Serve backend_invoice.html when accessing "/"
app.get('/', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'backend_invoice.html');
    res.sendFile(filePath, (err) => {
        if (err) {
            console.error('Error serving backend_invoice.html:', err);
            res.status(500).send('Internal Server Error');
        }
    });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
