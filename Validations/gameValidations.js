import Joi from 'joi';


// valid category
// 'xbox', 'pc', 'ps4', 'upcomingGames', 'bestSellers', 'newReleases',
// 'comingSoon', 'preOrders', 'hotGames', 'giftCard', 'steam', 'topSeller',
// 'nitendo', 'merchandise', 'cryptoCards'
export const gameSchema = Joi.object({
    sku: Joi.string().required(),
    category: Joi.string().valid(
        'XBOX', 'PC', 'PS4', 'UPCOMINGGAMES', 'BESTSELLERS', 'NEWRELEASES',
        'COMINGSOON', 'PREORDERS', 'HOTGAMES', 'GIFTCARD', 'STEAM', 'TOPSELLER',
        'NITENDO', 'MERCHANDISE', 'CRYPTOCARDS'
    ),
    platforms: Joi.array().items(Joi.string()),
    platform: Joi.string(),
    stock: Joi.number(),
    editions: Joi.array().items(Joi.string()),
    languages: Joi.array().items(Joi.string()),
    region: Joi.array().items(Joi.string()),
    genre: Joi.array().items(Joi.string()),
    developer: Joi.string().allow(''),
    releaseDate: Joi.date(),
    publisher: Joi.string().allow(''),
    delivery: Joi.string().allow(''),
    title: Joi.string().required(),
    bulletPoints: Joi.array().items(Joi.string()),
    description: Joi.string().allow(''), // Assuming HTML content
    price: Joi.number().required(),
    discount: Joi.number(),
    offer: Joi.object({
        discount: Joi.number(),
        startDate: Joi.date(),
        endDate: Joi.date(),
        isActive: Joi.boolean()
    }),
    images: Joi.array().items(Joi.object({
        url: Joi.string().required(),
        cloudinaryId: Joi.string().required()
    }))
});


export const updateGameSchema = Joi.object({
    sku: Joi.string(),
    category: Joi.string().valid(
        'XBOX', 'PC', 'PS4', 'UPCOMINGGAMES', 'BESTSELLERS', 'NEWRELEASES',
        'COMINGSOON', 'PREORDERS', 'HOTGAMES', 'GIFTCARD', 'STEAM', 'TOPSELLER',
        'NITENDO', 'MERCHANDISE', 'CRYPTOCARDS'
    ),
    platforms: Joi.array().items(Joi.string()),
    platform: Joi.string(),
    stock: Joi.number(),
    editions: Joi.array().items(Joi.string()),
    languages: Joi.array().items(Joi.string()),
    region: Joi.array().items(Joi.string()),
    genre: Joi.array().items(Joi.string()),
    developer: Joi.string().allow(''),
    releaseDate: Joi.date(),
    publisher: Joi.string().allow(''),
    delivery: Joi.string().allow(''),
    title: Joi.string(),
    bulletPoints: Joi.array().items(Joi.string()),
    description: Joi.string().allow(''),
    price: Joi.number(),
    discount: Joi.number(),
    offer: Joi.object({
        discount: Joi.number(),
        startDate: Joi.date(),
        endDate: Joi.date(),
        isActive: Joi.boolean()
    }),
    images: Joi.array().items(Joi.object({
        url: Joi.string().required(),
        cloudinaryId: Joi.string().required()
    }))
});



