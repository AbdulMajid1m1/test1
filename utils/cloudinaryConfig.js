import { CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET, CLOUDINARY_CLOUD_NAME } from '../config/config.js';
import fs from 'fs';
import cloudinary from './cloudinaryInit.js';





export const cloudinaryConfig = cloudinary.config({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET,
});



export const uploadImages = async (files) => {
    const uploader = async (path) => await cloudinary.v2.uploader.upload(path, { folder: "games" });
    const urls = [];

    for (const file of files) {
        const { path } = file;
        const newPath = await uploader(path);
        urls.push(newPath);
        fs.unlinkSync(path);
    }

    return urls.map(url => ({ url: url.url, cloudinaryId: url.public_id }));
};
