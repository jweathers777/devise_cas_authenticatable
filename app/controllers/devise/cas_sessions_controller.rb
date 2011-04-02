class Devise::CasSessionsController < Devise::SessionsController  
  unloadable
  
  def service
    if signed_in?(resource_name)
      redirect_to after_sign_in_path_for(resource_name)
    else
      redirect_to root_url
    end
  end
  
  def destroy
    # if :cas_create_user is false a CAS session might be open but not signed_in
    # in such case we destroy the session here
    if signed_in?(resource_name)
      if ticket = session[:cas_last_valid_ticket]
        resource_class.delete_service_session_lookup(ticket)
      end
      sign_out(resource_name)
    else
      reset_session
    end
    destination = request.protocol
    destination << request.host
    destination << ":#{request.port.to_s}" unless request.port == 80
    destination << after_sign_out_path_for(resource_name)
    redirect_to(::Devise.cas_client.logout_url(destination))
  end

  def single_sign_out
    if ::Devise.cas_enable_single_sign_out
      session_index = read_session_index
      if session_index
        logger.debug "Intercepted single-sign-out request for CAS session #{session_index}."
        session_id = resource_class.read_service_session_lookup(session_index)
        if session_id
          destroy_cas_session(session_id, session_index)
        end
      end
    else
      logger.warn "Ignoring CAS single-sign-out request as feature is not currently enabled."
    end

    render :nothing => true
  end

  private

  def read_session_index
    if request.headers['CONTENT_TYPE'] =~ %r{^multipart/}
      false
    elsif request.post? && params['logoutRequest'] =~
        %r{^<samlp:LogoutRequest.*?<samlp:SessionIndex>(.*)</samlp:SessionIndex>}m
      $~[1]
    else
      false
    end
  end

  def current_sess_store
    if ::Rails::VERSION::STRING =~ /^3[0-9.]+/
      ::Rails.application.config.session_store
    else
      ActionController::Base.session_store
    end
  rescue NameError => e
    ActionController::Base.session_options[:database_manager]
  end

  def destroy_cas_session(session_id, session_index)
    if session = current_sess_store::Session.find_by_session_id(session_id)
      ticket = session.data['cas_last_valid_ticket'] || session_index
      resource_class.delete_service_session_lookup(ticket)
      session.destroy
      
      logger.debug("Destroyed #{session.inspect} for session #{session_id} corresponding to service ticket #{session_index}.")
    else
      logger.debug("Data for session #{session_id} was not found. It may have already been cleared by a local CAS logout request.")
    end
  end
end
