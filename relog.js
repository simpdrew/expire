/**
 * Module used to reload a cookie
 */

const request = require('request-promise')
const getVerificationInputs = require('./getVerificationInputs').func

module.exports = {
	/**
	 * Get the RequestVerificationToken
	 *
	 * @param {string} Cookie
	 */
	getVerification: cookie => {
		return new Promise((resolve, reject) => {
			return request({
				url: 'https://www.roblox.com/my/account#!/security',
				resolveWithFullResponse: true,
				headers: {
					cookie: `.ROBLOSECURITY=_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_72CC72B2FD932933061B47DA131806C137FDA9904C61E40C7A775B18333E3AF56CB0CA6F96727A4C7017CEF44E412074DE3B4522E74FDDC2BB91054D2A3E8D417EC5CF3C47BEA9F6E648B8506050235107DF3E376B85F43BC3DD635598B81F6483728B5145D93BFF2804608FE5ABDD3ABF34086AE700D3205F7C1AA8F8A33601B6D6CB627B60F3017F98006781D44226BAEB09F3603E43231030AF2BFF4A0A709594688E16590409BA47F54FE9BB5907E1D6DECE47D05ED3715C2C10BC8293B2BBB62717C5CD4684709797254F067BE6C3691EA69317F775D93129C9A2DDC15EAECF032B52A062A3830E0430C7BE5535B93DACF0EE7608C6908DCA3346636C8C906B2DEC10DC30D5BB60F684BDBD109D250554A64459CA42E4AA57A2D9BD081D96DE4DF39F138AD63B376290EAADF7F7C4FB236C6C352E96764BAB53849BB2E79217BC6E`
				}
			}).then(res => {
				const inputs = getVerificationInputs({ html: res.body })
				var match

				if (res.headers && res.headers['set-cookie']) {
					match = res.headers['set-cookie']
						.toString()
						.match(/__RequestVerificationToken=(.*?);/)
				}

				resolve({
					inputs: inputs,
					header: match && match[1]
				})
			})
		})
	},

	/**
	 * Get the general token
	 *
	 * @param {string} Cookie
	 */
	getGeneralToken: async cookie => {
		return new Promise((resolve, reject) => {
			return request({
				// This will never actually sign you out because an X-CSRF-TOKEN isn't provided, only received
				url: 'https://api.roblox.com/sign-out/v1', // REQUIRES https. Thanks for letting me know, ROBLOX...
				resolveWithFullResponse: true,
				method: 'POST',
				headers: {
					cookie: `.ROBLOSECURITY=${cookie}`
				}
			}).catch(res => {
				var xcsrf = res.response.headers['x-csrf-token']
				if (xcsrf) {
					resolve(xcsrf)
				} else {
					reject('Did not receive X-CSRF-TOKEN')
				}
			})
		})
	},

	/**
	 * Reload a cookie
	 *
	 * @param {string} Cookie
	 */
	relog: cookie => {
		return new Promise(async (resolve, reject) => {
			if (!cookie) reject('no cookie supplied?')

			// Get verification token
			const verificationToken = await module.exports.getVerification(
				cookie
			)

			if (!verificationToken.header) return reject('Bad cookie')

			// Get general token
			const generalToken = await module.exports.getGeneralToken(cookie)
			// Refresh the token
			return request({
				url:
					'https://www.roblox.com/authentication/signoutfromallsessionsandreauthenticate',
				method: 'POST',
				resolveWithFullResponse: true,
				headers: {
					'X-CSRF-TOKEN': generalToken,
					cookie: `.ROBLOSECURITY=_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_72CC72B2FD932933061B47DA131806C137FDA9904C61E40C7A775B18333E3AF56CB0CA6F96727A4C7017CEF44E412074DE3B4522E74FDDC2BB91054D2A3E8D417EC5CF3C47BEA9F6E648B8506050235107DF3E376B85F43BC3DD635598B81F6483728B5145D93BFF2804608FE5ABDD3ABF34086AE700D3205F7C1AA8F8A33601B6D6CB627B60F3017F98006781D44226BAEB09F3603E43231030AF2BFF4A0A709594688E16590409BA47F54FE9BB5907E1D6DECE47D05ED3715C2C10BC8293B2BBB62717C5CD4684709797254F067BE6C3691EA69317F775D93129C9A2DDC15EAECF032B52A062A3830E0430C7BE5535B93DACF0EE7608C6908DCA3346636C8C906B2DEC10DC30D5BB60F684BDBD109D250554A64459CA42E4AA57A2D9BD081D96DE4DF39F138AD63B376290EAADF7F7C4FB236C6C352E96764BAB53849BB2E79217BC6E`
				},
				form: {
					__RequestVerificationToken:
						verificationToken.inputs.__RequestVerificationToken
				}
			})
				.then(res => {
					const cookies = res.headers['set-cookie']

					if (cookies) {
						const newCookie = cookies
							.toString()
							.match(/\.ROBLOSECURITY=(.*?);/)[1]

						resolve(newCookie)
					} else {
						reject('Bad Roblox response')
					}
				})
				.catch(() => {
					reject('Bad Roblox response')
				})
		})
	}
}
