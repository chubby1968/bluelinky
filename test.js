const config = require('./config.json');
const BlueLinky = require('./dist/index');

const authCreds = {
	username: config.username,
	password: config.password
}

const test = async () => {

	const client = new BlueLinky(authCreds);
	// do login
	await client.login();

	const vehicle = await client.registerVehicle(config.vin, config.pin);
	const status = await vehicle.status(true);

	console.log(status);
}

test();
