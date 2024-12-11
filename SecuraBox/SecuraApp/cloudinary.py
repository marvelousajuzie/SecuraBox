import cloudinary.uploader



def upload_to_cloudinary(file, folder="project_folder", tags=None, transformation=None):
    tags = tags or ['certificate_upload']
    transformation = transformation or {"width": 300, "height": 300, "crop": "fill"}
    try:
        return cloudinary.uploader.upload(
            file,
            folder=folder,
            tags=tags,
            transformation=transformation
        )
    except Exception as e:
        raise Exception(f"Cloudinary upload failed: {e}")
